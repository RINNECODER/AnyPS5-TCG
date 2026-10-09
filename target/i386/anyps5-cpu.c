#include "qemu/osdep.h"
#include "qemu/anyps5-cpu.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qemu/queue.h"
#include "qemu/units.h"
#include "qemu/rcu.h"
#include "qemu/atomic.h"
#include "qemu/cutils.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "cpu.h"
#include "anyps5-cpu-internal.h"
#include "exec/address-spaces.h"
#include "exec/cpu-common.h"
#include "exec/cputlb.h"
#include "exec/exec-all.h"
#include "exec/tb-flush.h"
#include "exec/translation-block.h"
#include "accel/tcg/cpu-ops.h"
#include "accel/tcg/internal-common.h"
#include "accel/tcg/tcg-accel-ops.h"
#include "tcg/tcg.h"
#include "tcg/startup.h"
#include "system/cpus.h"
#include "system/tcg.h"
#include "gdbstub/enums.h"

#define ANYPS5_EXCP_STOP (EXCP_INTERRUPT + 20)
#define ANYPS5_MAX_RANGES 256
#define ANYPS5_MAX_GATES 256
#define ANYPS5_MAX_BACKINGS 256
/* Architectural segment/flags state which may vary within the fixed profile. */
#define ANYPS5_CONTEXT_HFLAGS (HF_INHIBIT_IRQ_MASK | HF_SS32_MASK | \
                               HF_ADDSEG_MASK | HF_TF_MASK | HF_RF_MASK | \
                               HF_AC_MASK)

typedef struct AnyPS5QemuUserState {
    target_ulong regs[CPU_NB_REGS];
    target_ulong rip;
    target_ulong rflags;
    SegmentCache segs[6];
    uint32_t user_hflags;
    unsigned fpstt;
    uint16_t fpus, fpuc, fpop, fpcs, fpds;
    uint64_t fpip, fpdp;
    uint8_t fptags[8];
    FPReg fpregs[8];
    uint8_t ymm[16][32];
    uint32_t mxcsr;
    /* These softfloat structures contain scalars, enums and bools, no pointers. */
    float_status fp_status, mmx_status, sse_status;
} AnyPS5QemuUserState;

struct AnyPS5QemuContext {
    AnyPS5QemuUserState *state;
    AnyPS5QemuContext *next;
    QLIST_ENTRY(AnyPS5QemuContext) live;
};

typedef struct AnyPS5QemuBacking {
    uint64_t id;
    void *host;
    size_t size;
    size_t aliases;
    bool automatic;
    MemoryRegion region;
} AnyPS5QemuBacking;

typedef struct AnyPS5QemuProtection {
    size_t offset;
    size_t size;
    unsigned permissions;
} AnyPS5QemuProtection;

typedef struct AnyPS5QemuRange {
    uint64_t address;
    size_t size;
    AnyPS5QemuBacking *backing;
    GArray *protections;
    MemoryRegion region;
} AnyPS5QemuRange;

typedef struct AnyPS5QemuGate {
    uint64_t address;
    uint64_t id;
} AnyPS5QemuGate;

struct AnyPS5QemuCpu {
    X86CPU *x86;
    QemuThread owner;
    AnyPS5QemuRange *ranges[ANYPS5_MAX_RANGES];
    size_t range_count;
    AnyPS5QemuBacking *backings[ANYPS5_MAX_BACKINGS];
    size_t backing_count;
    uint64_t next_backing_id;
    AnyPS5QemuGate gates[ANYPS5_MAX_GATES];
    size_t gate_count;
    AnyPS5QemuRunResult stopped;
    bool pending;
    bool running;
    bool requested_stop;
    /*
     * Retain handles for ABA safety; search only live contexts.
     */
    AnyPS5QemuContext *contexts;
    QLIST_HEAD(, AnyPS5QemuContext) live_contexts;
    SegmentCache context_cs, context_ss;
    uint32_t context_profile_hflags;
    char error[256];
};

static AnyPS5QemuCpu *active_cpu;
static bool core_initialized;
static TCGCPUOps bridge_ops;

static int fail(AnyPS5QemuCpu *cpu, const char *message)
{
    if (cpu) {
        pstrcpy(cpu->error, sizeof(cpu->error), message);
    }
    return -1;
}

static bool on_owner(AnyPS5QemuCpu *cpu)
{
    return cpu && active_cpu == cpu && qemu_thread_is_self(&cpu->owner);
}

static bool same_segment(const SegmentCache *a, const SegmentCache *b)
{
    return a->selector == b->selector && a->base == b->base &&
           a->limit == b->limit && a->flags == b->flags;
}

static bool context_profile(AnyPS5QemuCpu *cpu)
{
    CPUX86State *env = &cpu->x86->env;

    return env->cr[0] == (CR0_PE_MASK | CR0_ET_MASK) &&
           env->cr[4] == (CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK |
                          CR4_OSXSAVE_MASK) &&
           env->efer == (MSR_EFER_LME | MSR_EFER_LMA | MSR_EFER_SCE) &&
           env->xcr0 == (XSTATE_FP_MASK | XSTATE_SSE_MASK | XSTATE_YMM_MASK) &&
           (env->hflags & ~ANYPS5_CONTEXT_HFLAGS) ==
               cpu->context_profile_hflags &&
           env->hflags2 == HF2_GIF_MASK &&
           !(env->eflags & (IOPL_MASK | VM_MASK | VIF_MASK | VIP_MASK)) &&
           same_segment(&env->segs[R_CS], &cpu->context_cs) &&
           same_segment(&env->segs[R_SS], &cpu->context_ss);
}

static int context_idle(AnyPS5QemuCpu *cpu)
{
    /* Reject a non-current CPU without dereferencing it for an error.
     * Callers must not reuse CPU/context pointers after CPU destruction.
     */
    if (!on_owner(cpu)) {
        return fail(NULL, "Context access requires its CPU owner thread");
    }
    if (cpu->running) {
        return fail(cpu, "Context access requires the idle CPU owner");
    }
    return 0;
}

static AnyPS5QemuContext *find_context(AnyPS5QemuCpu *cpu,
                                     const AnyPS5QemuContext *context)
{
    AnyPS5QemuContext *entry;

    /* Compare membership before dereferencing any caller-supplied pointer. */
    QLIST_FOREACH(entry, &cpu->live_contexts, live) {
        if (entry == context) {
            return entry;
        }
    }
    return NULL;
}

static void capture_context(AnyPS5QemuCpu *cpu, AnyPS5QemuUserState *state)
{
    CPUX86State *env = &cpu->x86->env;

    memcpy(state->regs, env->regs, sizeof(state->regs));
    state->rip = env->eip;
    /* cpu_exec exit already materializes CC/DF. Public Set may replace it. */
    state->rflags = env->eflags | 2;
    memcpy(state->segs, env->segs, sizeof(state->segs));
    state->user_hflags = env->hflags & ANYPS5_CONTEXT_HFLAGS;
    state->fpstt = env->fpstt;
    state->fpus = env->fpus;
    state->fpuc = env->fpuc;
    state->fpop = env->fpop;
    state->fpcs = env->fpcs;
    state->fpds = env->fpds;
    state->fpip = env->fpip;
    state->fpdp = env->fpdp;
    memcpy(state->fptags, env->fptags, sizeof(state->fptags));
    /* Physical slots preserve x87 TOP/tags and the aliased MMX bits. */
    memcpy(state->fpregs, env->fpregs, sizeof(state->fpregs));
    for (unsigned i = 0; i < 16; i++) {
        memcpy(state->ymm[i], &env->xmm_regs[i], 32);
    }
    state->mxcsr = env->mxcsr;
    state->fp_status = env->fp_status;
    state->mmx_status = env->mmx_status;
    state->sse_status = env->sse_status;
}

int anyps5_qemu_cpu_context_create(AnyPS5QemuCpu *cpu,
                                 AnyPS5QemuContext **context)
{
    AnyPS5QemuContext *entry;

    if (context_idle(cpu)) {
        return -1;
    }
    if (!context || !context_profile(cpu)) {
        return fail(cpu, "Context creation requires an output and fixed application profile");
    }
    entry = g_try_new0(AnyPS5QemuContext, 1);
    if (!entry) {
        return fail(cpu, "Cannot allocate guest context");
    }
    entry->state = g_try_new0(AnyPS5QemuUserState, 1);
    if (!entry->state) {
        g_free(entry);
        return fail(cpu, "Cannot allocate guest register state");
    }
    capture_context(cpu, entry->state);
    entry->next = cpu->contexts;
    cpu->contexts = entry;
    QLIST_INSERT_HEAD(&cpu->live_contexts, entry, live);
    *context = entry;
    return 0;
}

int anyps5_qemu_cpu_context_save(AnyPS5QemuCpu *cpu, AnyPS5QemuContext *context)
{
    AnyPS5QemuContext *entry;

    if (context_idle(cpu)) {
        return -1;
    }
    entry = find_context(cpu, context);
    if (!entry || !context_profile(cpu)) {
        return fail(cpu, "Context save requires a live CPU-owned context and fixed profile");
    }
    capture_context(cpu, entry->state);
    return 0;
}

int anyps5_qemu_cpu_context_restore(AnyPS5QemuCpu *cpu,
                                  const AnyPS5QemuContext *context)
{
    AnyPS5QemuContext *entry;
    const AnyPS5QemuUserState *state;
    CPUX86State *env;

    if (context_idle(cpu)) {
        return -1;
    }
    entry = find_context(cpu, context);
    if (!entry || !context_profile(cpu)) {
        return fail(cpu, "Context restore requires a live CPU-owned context and fixed profile");
    }
    state = entry->state;
    if (!same_segment(&state->segs[R_CS], &cpu->context_cs) ||
        !same_segment(&state->segs[R_SS], &cpu->context_ss) ||
        (state->user_hflags & ~ANYPS5_CONTEXT_HFLAGS) || state->fpstt >= 8 ||
        !(state->rflags & 2) ||
        (state->rflags & (IOPL_MASK | VM_MASK | VIF_MASK | VIP_MASK)) ||
        (state->mxcsr & ~0xffffu)) {
        return fail(cpu, "Invalid saved guest architectural state");
    }
    for (unsigned i = 0; i < 8; i++) {
        if (state->fptags[i] > 1) {
            return fail(cpu, "Invalid saved x87 tag state");
        }
    }
    env = &cpu->x86->env;
    memcpy(env->regs, state->regs, sizeof(state->regs));
    env->eip = state->rip;
    env->eflags = state->rflags;
    env->cc_src = state->rflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->cc_dst = env->cc_src2 = 0;
    env->cc_op = CC_OP_EFLAGS;
    env->df = 1 - 2 * ((state->rflags >> 10) & 1);
    /* The bridge's initial CS/SS descriptors are not hardware reset caches.
     * Restore caches with their validated user hflags, without reloading CS/SS
     * through load_seg_cache, which would change this fixed CPL3/64-bit mode.
     */
    memcpy(env->segs, state->segs, sizeof(state->segs));
    env->hflags = cpu->context_profile_hflags | state->user_hflags;
    env->fpstt = state->fpstt;
    env->fpus = state->fpus;
    cpu_set_fpuc(env, state->fpuc);
    env->fpop = state->fpop;
    env->fpcs = state->fpcs;
    env->fpds = state->fpds;
    env->fpip = state->fpip;
    env->fpdp = state->fpdp;
    memcpy(env->fptags, state->fptags, sizeof(state->fptags));
    memcpy(env->fpregs, state->fpregs, sizeof(state->fpregs));
    for (unsigned i = 0; i < 16; i++) {
        memcpy(&env->xmm_regs[i], state->ymm[i], 32);
    }
    cpu_set_mxcsr(env, state->mxcsr);
    /* Control helpers set derived rounding/DAZ/FTZ but clear accrued flags.
     * The complete pointer-free status retains all pending exception bits.
     */
    env->fp_status = state->fp_status;
    env->mmx_status = state->mmx_status;
    env->sse_status = state->sse_status;
    return 0;
}

int anyps5_qemu_cpu_context_destroy(AnyPS5QemuCpu *cpu,
                                  AnyPS5QemuContext *context)
{
    AnyPS5QemuContext *entry;

    if (context_idle(cpu)) {
        return -1;
    }
    entry = find_context(cpu, context);
    if (!entry) {
        return fail(cpu, "Context destruction requires a live CPU-owned context");
    }
    QLIST_REMOVE(entry, live);
    g_free(entry->state);
    entry->state = NULL;
    /* Keep the small handle until CPU destruction, preventing address reuse
     * from accepting a retired context during this CPU's lifetime.
     */
    return 0;
}

static AnyPS5QemuRange *find_range(AnyPS5QemuCpu *cpu, uint64_t address,
                                  uint64_t size)
{
    size_t i;

    for (i = 0; i < cpu->range_count; i++) {
        AnyPS5QemuRange *range = cpu->ranges[i];

        if (address >= range->address && size <= range->size &&
            address - range->address <= range->size - size) {
            return range;
        }
    }
    return NULL;
}

static void save_stop(AnyPS5QemuCpu *cpu, enum AnyPS5QemuStop reason,
                      uint64_t address, uint32_t vector, uint32_t error_code)
{
    cpu->stopped.reason = reason;
    cpu->stopped.address = address;
    cpu->stopped.vector = vector;
    cpu->stopped.error_code = error_code;
    cpu->pending = true;
}

static unsigned range_permissions(AnyPS5QemuRange *range, uint64_t address,
                                  size_t size)
{
    size_t offset = address - range->address;
    size_t end = offset + size;
    size_t cursor = offset;
    unsigned permissions = 7;

    for (size_t i = 0; i < range->protections->len; i++) {
        AnyPS5QemuProtection *p = &g_array_index(range->protections,
                                               AnyPS5QemuProtection, i);
        if (offset < p->offset + p->size && p->offset < end) {
            if (p->offset > cursor) {
                return 0;
            }
            permissions &= p->permissions;
            cursor = MIN(end, p->offset + p->size);
            if (cursor == end) {
                return permissions;
            }
        }
    }
    return 0;
}

static uint64_t range_access_fault(AnyPS5QemuRange *range, uint64_t address,
                                  size_t size, unsigned permission)
{
    size_t cursor = address - range->address;
    size_t end = cursor + size;

    for (size_t i = 0; i < range->protections->len; i++) {
        AnyPS5QemuProtection *p = &g_array_index(range->protections,
                                               AnyPS5QemuProtection, i);
        if (p->offset + p->size <= cursor) {
            continue;
        }
        if (p->offset > cursor || !(p->permissions & permission)) {
            return range->address + cursor;
        }
        cursor = MIN(end, p->offset + p->size);
        if (cursor == end) {
            break;
        }
    }
    return range->address + cursor;
}

static bool range_page_subdivided(AnyPS5QemuRange *range, uint64_t address)
{
    size_t first = (address & TARGET_PAGE_MASK) - range->address;
    size_t last = first + TARGET_PAGE_SIZE;
    unsigned permissions = 8;

    for (size_t i = 0; i < range->protections->len; i++) {
        AnyPS5QemuProtection *p = &g_array_index(range->protections,
                                               AnyPS5QemuProtection, i);
        if (p->offset >= last || first >= p->offset + p->size) {
            continue;
        }
        if (permissions != 8 && permissions != p->permissions) {
            return true;
        }
        permissions = p->permissions;
    }
    return false;
}

static AnyPS5QemuBacking *find_backing(AnyPS5QemuCpu *cpu, uint64_t id)
{
    for (size_t i = 0; i < cpu->backing_count; i++) {
        if (cpu->backings[i]->id == id) {
            return cpu->backings[i];
        }
    }
    return NULL;
}

static bool executable_byte(AnyPS5QemuCpu *cpu, uint64_t pc, size_t offset,
                            uint8_t *value)
{
    AnyPS5QemuRange *range;
    uint64_t address;

    if (offset >= 15 || pc > 0x7fffffffffffULL - offset) {
        return false;
    }
    address = pc + offset;
    range = find_range(cpu, address, 1);
    if (!range || !(range_permissions(range, address, 1) & ANYPS5_QEMU_EXECUTE)) {
        return false;
    }
    *value = ((uint8_t *)range->backing->host)[range->region.alias_offset +
                                              address - range->address];
    return true;
}

static bool complete_modrm(AnyPS5QemuCpu *cpu, uint64_t pc, size_t offset,
                           uint8_t modrm)
{
    unsigned mod = modrm >> 6;
    unsigned rm = modrm & 7;
    unsigned displacement = mod == 1 ? 1 : mod == 2 ? 4 : 0;
    uint8_t byte;

    if (mod == 3) {
        return true;
    }
    if (rm == 4) {
        if (!executable_byte(cpu, pc, ++offset, &byte)) {
            return false;
        }
        if (mod == 0 && (byte & 7) == 5) {
            displacement = 4;
        }
    } else if (mod == 0 && rm == 5) {
        displacement = 4;
    }
    while (displacement--) {
        if (!executable_byte(cpu, pc, ++offset, &byte)) {
            return false;
        }
    }
    return true;
}

static bool application_service_instruction(AnyPS5QemuCpu *cpu, uint64_t pc)
{
    uint8_t opcode, second, modrm;
    size_t offset = 0;
    bool lock = false;
    bool data_or_rep = false;
    bool rex_seen = false;
    bool legacy_after_rex = false;
    unsigned rex_r = 0;

    while (executable_byte(cpu, pc, offset, &opcode)) {
        if ((opcode >= 0x40 && opcode <= 0x4f) || opcode == 0x66 ||
            opcode == 0x67 || opcode == 0xf0 || opcode == 0xf2 ||
            opcode == 0xf3 || opcode == 0x26 || opcode == 0x2e ||
            opcode == 0x36 || opcode == 0x3e || opcode == 0x64 ||
            opcode == 0x65) {
            lock |= opcode == 0xf0;
            data_or_rep |= opcode == 0x66 || opcode == 0xf2 || opcode == 0xf3;
            if (opcode >= 0x40 && opcode <= 0x4f) {
                rex_seen = true;
                rex_r = (opcode & 4) << 1;
            } else {
                legacy_after_rex |= rex_seen;
            }
            offset++;
            continue;
        }
        /* Invalid LOCK and incomplete/overlong encodings remain QEMU's faults. */
        if (lock) {
            return false;
        }
        switch (opcode) {
        case 0xf4: case 0xfa: case 0xfb:
        case 0x6c: case 0x6d: case 0x6e: case 0x6f:
        case 0xec: case 0xed: case 0xee: case 0xef:
            return true;
        case 0xe4: case 0xe5: case 0xe6: case 0xe7:
            return executable_byte(cpu, pc, offset + 1, &second);
        case 0x0f:
            if (!executable_byte(cpu, pc, ++offset, &second)) {
                return false;
            }
            switch (second) {
            case 0x06: case 0x07: case 0x08: case 0x09:
            case 0x30: case 0x32: case 0x34: case 0x35:
                return true;
            case 0x20: case 0x21: case 0x22: case 0x23:
                if (!executable_byte(cpu, pc, offset + 1, &modrm) || legacy_after_rex) {
                    /* Leave mixed prefix ordering to the actual decoder. */
                    return false;
                }
                unsigned selector = ((modrm >> 3) & 7) | rex_r;
                if (second == 0x20 || second == 0x22) {
                    return selector == 0 || selector == 2 || selector == 3 ||
                           selector == 4 || selector == 8;
                }
                return selector < 8;
            case 0x00: case 0x01:
                if (!executable_byte(cpu, pc, ++offset, &modrm)) {
                    return false;
                }
                if (second == 0x00) {
                    unsigned group = (modrm >> 3) & 7;
                    return (group == 2 || group == 3) &&
                           complete_modrm(cpu, pc, offset, modrm);
                }
                unsigned group = (modrm >> 3) & 7;
                bool memory = (modrm & 0xc0) != 0xc0;
                if (modrm == 0xc8 || modrm == 0xc9 ||
                    (modrm == 0xd1 && (data_or_rep ||
                     !(cpu->x86->env.features[FEAT_1_ECX] & CPUID_EXT_XSAVE)))) {
                    return false;
                }
                bool service = (memory && (group == 2 || group == 3 || group == 7)) ||
                               group == 6 || modrm == 0xf8 || modrm == 0xd1;
                return service && complete_modrm(cpu, pc, offset, modrm);
            default:
                return false;
            }
        default:
            return false;
        }
    }
    return false;
}

static bool bridge_tlb_fill(CPUState *cs, vaddr address, int size,
                            MMUAccessType access_type, int mmu_idx,
                            bool probe, uintptr_t retaddr)
{
    AnyPS5QemuCpu *cpu = active_cpu;
    AnyPS5QemuRange *range;
    unsigned permission;
    unsigned permissions;

    g_assert(cpu && CPU(cpu->x86) == cs);
    permission = access_type == MMU_INST_FETCH ? ANYPS5_QEMU_EXECUTE :
                 access_type == MMU_DATA_STORE ? ANYPS5_QEMU_WRITE :
                                                ANYPS5_QEMU_READ;
    range = address <= 0x7fffffffffffULL ?
            find_range(cpu, address, size > 0 ? size : 1) : NULL;
    permissions = range ? range_permissions(range, address, size > 0 ? size : 1) : 0;
    if (!(permissions & permission)) {
        if (probe) {
            return false;
        }
        save_stop(cpu, ANYPS5_QEMU_FAULT,
                  range ? range_access_fault(range, address,
                                             size > 0 ? size : 1, permission) :
                          address, EXCP0E_PAGE,
                  (range ? PG_ERROR_P_MASK : 0) | PG_ERROR_U_MASK |
                  (access_type == MMU_DATA_STORE ? PG_ERROR_W_MASK : 0) |
                  (access_type == MMU_INST_FETCH ? PG_ERROR_I_D_MASK : 0));
        cs->exception_index = ANYPS5_EXCP_STOP;
        cpu_loop_exit_restore(cs, retaddr);
    }
    tlb_set_page(cs, address & TARGET_PAGE_MASK, address & TARGET_PAGE_MASK,
                 permissions, mmu_idx,
                 range_page_subdivided(range, address) ? 1 : TARGET_PAGE_SIZE);
    return true;
}

static void bridge_interrupt(CPUState *cs)
{
    AnyPS5QemuCpu *cpu = active_cpu;
    CPUX86State *env = cpu_env(cs);

    save_stop(cpu, ANYPS5_QEMU_UNSUPPORTED, env->cr[2],
              cs->exception_index, env->error_code);
    /* The host consumed this exception; there is no pending IDT delivery. */
    env->old_exception = -1;
}

bool anyps5_qemu_cpu_intercept_syscall(CPUX86State *env, int next_eip_addend)
{
    AnyPS5QemuCpu *cpu = active_cpu;
    CPUState *cs = env_cpu(env);

    if (!cpu || CPU(cpu->x86) != cs || !cpu->running) {
        return false;
    }
    env->regs[R_ECX] = env->eip + next_eip_addend;
    env->regs[R_R11] = cpu_compute_eflags(env) & ~RF_MASK;
    env->eip += next_eip_addend;
    save_stop(cpu, ANYPS5_QEMU_SYSCALL, 0, 0, 0);
    cs->exception_index = ANYPS5_EXCP_STOP;
    cpu_loop_exit(cs);
}

static void initialize_core(void)
{
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    qemu_init_cpu_loop();
    bql_lock();
    module_call_init(MODULE_INIT_QOM);
    cpu_exec_init_all();
    tcg_allowed = true;
    mttcg_enabled = false;
    page_init();
    tb_htable_init();
    tcg_init(32 * MiB, 0, 1);
    tcg_prologue_init();
    bql_unlock();
}

AnyPS5QemuCpu *anyps5_qemu_cpu_create(char *error, size_t error_size)
{
    AnyPS5QemuCpu *cpu;
    CPUState *cs;
    CPUX86State *env;
    QemuCond *halt_cond;
    Error *local_error = NULL;

    if (active_cpu) {
        if (error && error_size) {
            pstrcpy(error, error_size, "Only one CPU bridge context is supported");
        }
        return NULL;
    }
    if (!core_initialized) {
        initialize_core();
        core_initialized = true;
    }
    cpu = g_new0(AnyPS5QemuCpu, 1);
    qemu_thread_get_self(&cpu->owner);
    bql_lock();
    cpu->x86 = X86_CPU(object_new("Haswell-v4-x86_64-cpu"));
    cs = CPU(cpu->x86);
    env = &cpu->x86->env;
    active_cpu = cpu;
    anyps5_qemu_cpu_install_ops(cs, &bridge_ops);
    if (!anyps5_qemu_cpu_prepare_model(cpu->x86, &local_error)) {
        if (error && error_size) {
            pstrcpy(error, error_size, error_get_pretty(local_error));
        }
        error_free(local_error);
        object_unref(OBJECT(cpu->x86));
        active_cpu = NULL;
        g_free(cpu);
        bql_unlock();
        return NULL;
    }
    bridge_ops.tlb_fill = bridge_tlb_fill;
    bridge_ops.do_interrupt = bridge_interrupt;
    bridge_ops.debug_excp_handler = NULL;
    cs->cluster_index = 0;
    cpu_list_add(cs);
    if (!tcg_exec_realizefn(cs, &local_error)) {
        if (error && error_size) {
            pstrcpy(error, error_size, error_get_pretty(local_error));
        }
        error_free(local_error);
        cpu_list_remove(cs);
        object_unref(OBJECT(cpu->x86));
        active_cpu = NULL;
        g_free(cpu);
        bql_unlock();
        return NULL;
    }
    cs->num_ases = 1;
    halt_cond = cs->halt_cond;
    cs->halt_cond = NULL;
    cpu_address_space_init(cs, 0, "anyps5-cpu", cs->memory);
    cs->halt_cond = halt_cond;
    cs->created = true;
    qemu_thread_get_self(cs->thread);
    tcg_cpu_init_cflags(cs, false);
    cs->singlestep_enabled = SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER;
    /* Normally supplied by CPU reset; no machine reset runs in this bridge. */
    cs->cflags_next_tb = -1;
    cs->neg.can_do_io = true;
    cs->exception_index = -1;
    env->hflags = HF_PE_MASK | HF_CS32_MASK | HF_SS32_MASK |
                  HF_CS64_MASK | HF_LMA_MASK | HF_OSFXSR_MASK |
                  HF_AVX_EN_MASK | 3;
    env->hflags2 = HF2_GIF_MASK;
    env->cr[0] = CR0_PE_MASK | CR0_ET_MASK;
    env->cr[4] = CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK | CR4_OSXSAVE_MASK;
    env->efer = MSR_EFER_LME | MSR_EFER_LMA | MSR_EFER_SCE;
    env->xcr0 = XSTATE_FP_MASK | XSTATE_SSE_MASK | XSTATE_YMM_MASK;
    env->a20_mask = -1;
    env->eflags = 2;
    env->old_exception = -1;
    env->segs[R_CS].selector = 0x33;
    env->segs[R_SS].selector = 0x2b;
    cpu->x86->phys_bits = 48;
    cpu_init_fp_statuses(env);
    for (unsigned i = 0; i < 8; i++) {
        env->fptags[i] = 1;
    }
    cpu_set_fpuc(env, 0x37f);
    cpu_set_mxcsr(env, 0x1f80);
    cpu->context_cs = env->segs[R_CS];
    cpu->context_ss = env->segs[R_SS];
    cpu->context_profile_hflags = env->hflags & ~ANYPS5_CONTEXT_HFLAGS;
    bql_unlock();
    return cpu;
}

int anyps5_qemu_cpu_register_backing(AnyPS5QemuCpu *cpu, void *host,
                                   size_t allocated_size, uint64_t *id)
{
    AnyPS5QemuBacking *backing;
    size_t host_page = qemu_real_host_page_size();
    uintptr_t base = (uintptr_t)host;

    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Backing registration requires the idle owner thread");
    }
    if (!host || !id || !allocated_size || base % host_page ||
        allocated_size % host_page || allocated_size > UINTPTR_MAX - base ||
        cpu->backing_count == ANYPS5_MAX_BACKINGS ||
        cpu->next_backing_id == UINT64_MAX) {
        return fail(cpu, "Backing must be a full stable host-page-aligned allocation");
    }
    for (size_t i = 0; i < cpu->backing_count; i++) {
        AnyPS5QemuBacking *other = cpu->backings[i];
        uintptr_t other_base = (uintptr_t)other->host;
        if (base < other_base + other->size &&
            other_base < base + allocated_size) {
            return fail(cpu, "Registered host backings overlap; reuse backing aliases");
        }
    }
    backing = g_new0(AnyPS5QemuBacking, 1);
    backing->id = ++cpu->next_backing_id;
    backing->host = host;
    backing->size = allocated_size;
    bql_lock();
    memory_region_init_ram_ptr(&backing->region, OBJECT(cpu->x86),
                               "anyps5-backing", allocated_size, host);
    cpu->backings[cpu->backing_count++] = backing;
    bql_unlock();
    *id = backing->id;
    return 0;
}

int anyps5_qemu_cpu_release_backing(AnyPS5QemuCpu *cpu, uint64_t id)
{
    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Backing release requires the idle owner thread");
    }
    for (size_t i = 0; i < cpu->backing_count; i++) {
        AnyPS5QemuBacking *backing = cpu->backings[i];
        if (backing->id != id) {
            continue;
        }
        if (backing->aliases) {
            return fail(cpu, "Backing still has guest aliases");
        }
        bql_lock();
        object_unparent(OBJECT(&backing->region));
        memmove(cpu->backings + i, cpu->backings + i + 1,
                (cpu->backing_count - i - 1) * sizeof(cpu->backings[0]));
        cpu->backing_count--;
        bql_unlock();
        drain_call_rcu();
        g_free(backing);
        return 0;
    }
    return fail(cpu, "Unknown backing ID");
}

int anyps5_qemu_cpu_map_alias(AnyPS5QemuCpu *cpu, uint64_t address,
                            uint64_t backing_id, size_t offset, size_t size,
                            unsigned permissions)
{
    AnyPS5QemuRange *range;
    AnyPS5QemuBacking *backing;
    AnyPS5QemuProtection protection = { 0, size, permissions };
    QemuCond *halt_cond;
    CPUState *cs;

    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Mapping requires the idle owner thread");
    }
    backing = find_backing(cpu, backing_id);
    if (!backing || !size || address >= 0x800000000000ULL ||
        size > 0x800000000000ULL - address ||
        address % TARGET_PAGE_SIZE || size % TARGET_PAGE_SIZE ||
        offset % TARGET_PAGE_SIZE || offset > backing->size ||
        size > backing->size - offset || (permissions & ~7u) ||
        cpu->range_count == ANYPS5_MAX_RANGES) {
        return fail(cpu, "Invalid logical guest alias or backing extent");
    }
    for (size_t i = 0; i < cpu->range_count; i++) {
        range = cpu->ranges[i];
        if (address < range->address + range->size &&
            range->address < address + size) {
            return fail(cpu, "Guest mappings overlap");
        }
    }
    range = g_new0(AnyPS5QemuRange, 1);
    range->address = address;
    range->size = size;
    range->backing = backing;
    range->protections = g_array_new(false, false, sizeof(protection));
    g_array_append_val(range->protections, protection);
    cs = CPU(cpu->x86);
    bql_lock();
    halt_cond = cs->halt_cond;
    cs->halt_cond = NULL;
    memory_region_init_alias(&range->region, OBJECT(cpu->x86), "anyps5-alias",
                             &backing->region, offset, size);
    memory_region_add_subregion(get_system_memory(), address, &range->region);
    cpu->ranges[cpu->range_count++] = range;
    backing->aliases++;
    cs->halt_cond = halt_cond;
    tlb_flush(cs);
    tb_flush(cs);
    bql_unlock();
    return 0;
}

int anyps5_qemu_cpu_map_borrowed(AnyPS5QemuCpu *cpu, uint64_t address,
                               void *host, size_t size, unsigned permissions)
{
    uint64_t id;
    if (anyps5_qemu_cpu_register_backing(cpu, host, size, &id)) {
        return -1;
    }
    if (anyps5_qemu_cpu_map_alias(cpu, address, id, 0, size, permissions)) {
        anyps5_qemu_cpu_release_backing(cpu, id);
        return -1;
    }
    find_backing(cpu, id)->automatic = true;
    return 0;
}

int anyps5_qemu_cpu_unmap(AnyPS5QemuCpu *cpu, uint64_t address)
{
    size_t i;
    CPUState *cs;
    QemuCond *halt_cond;

    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Unmapping requires the idle owner thread");
    }
    for (i = 0; i < cpu->range_count; i++) {
        AnyPS5QemuRange *range = cpu->ranges[i];
        if (range->address != address) {
            continue;
        }
        cs = CPU(cpu->x86);
        bql_lock();
        halt_cond = cs->halt_cond;
        cs->halt_cond = NULL;
        memory_region_del_subregion(get_system_memory(), &range->region);
        cs->halt_cond = halt_cond;
        tlb_flush(cs);
        tb_flush(cs);
        object_unparent(OBJECT(&range->region));
        memmove(cpu->ranges + i, cpu->ranges + i + 1,
                (cpu->range_count - i - 1) * sizeof(cpu->ranges[0]));
        cpu->range_count--;
        range->backing->aliases--;
        size_t remaining_gates = 0;
        for (size_t j = 0; j < cpu->gate_count; j++) {
            uint64_t gate_address = cpu->gates[j].address;
            if (gate_address >= range->address &&
                gate_address - range->address < range->size) {
                continue;
            }
            cpu->gates[remaining_gates++] = cpu->gates[j];
        }
        cpu->gate_count = remaining_gates;
        bql_unlock();
        /* FlatView callbacks still dereference embedded MemoryRegion storage. */
        drain_call_rcu();
        uint64_t automatic_backing = range->backing->automatic &&
            !range->backing->aliases ? range->backing->id : 0;
        g_array_free(range->protections, true);
        g_free(range);
        if (automatic_backing) {
            return anyps5_qemu_cpu_release_backing(cpu, automatic_backing);
        }
        return 0;
    }
    return fail(cpu, "Unmapping requires an existing range base");
}

int anyps5_qemu_cpu_invalidate(AnyPS5QemuCpu *cpu)
{
    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Invalidation requires the idle owner thread");
    }
    bql_lock();
    tlb_flush(CPU(cpu->x86));
    tb_flush(CPU(cpu->x86));
    bql_unlock();
    return 0;
}

static void append_protection(GArray *array, AnyPS5QemuProtection p)
{
    if (!p.size) {
        return;
    }
    if (array->len) {
        AnyPS5QemuProtection *last = &g_array_index(array,
            AnyPS5QemuProtection, array->len - 1);
        if (last->offset + last->size == p.offset &&
            last->permissions == p.permissions) {
            last->size += p.size;
            return;
        }
    }
    g_array_append_val(array, p);
}

static AnyPS5QemuRange *retain_fragment(AnyPS5QemuRange *source,
                                       uint64_t address, size_t size)
{
    AnyPS5QemuRange *fragment = g_new0(AnyPS5QemuRange, 1);
    size_t first = address - source->address;
    size_t last = first + size;

    fragment->address = address;
    fragment->size = size;
    fragment->backing = source->backing;
    fragment->protections = g_array_new(false, false,
                                        sizeof(AnyPS5QemuProtection));
    for (size_t i = 0; i < source->protections->len; i++) {
        AnyPS5QemuProtection p = g_array_index(source->protections,
                                              AnyPS5QemuProtection, i);
        size_t start = MAX(first, p.offset);
        size_t end = MIN(last, p.offset + p.size);
        if (start < end) {
            append_protection(fragment->protections, (AnyPS5QemuProtection) {
                start - first, end - start, p.permissions });
        }
    }
    return fragment;
}

static int change_guest_range(AnyPS5QemuCpu *cpu, uint64_t address, size_t size,
                              bool replace, uint64_t backing_id, size_t offset,
                              unsigned permissions)
{
    AnyPS5QemuRange *updated[ANYPS5_MAX_RANGES];
    AnyPS5QemuRange *removed[ANYPS5_MAX_RANGES];
    size_t physical_offsets[ANYPS5_MAX_RANGES];
    bool added[ANYPS5_MAX_RANGES];
    size_t needed = replace ? 1 : 0, count = 0, removed_count = 0;
    AnyPS5QemuBacking *backing = NULL;
    CPUState *cs;
    QemuCond *halt_cond;
    uint64_t end;

    if (!on_owner(cpu) || cpu->running || !size ||
        address >= 0x800000000000ULL || size > 0x800000000000ULL - address ||
        address % TARGET_PAGE_SIZE || size % TARGET_PAGE_SIZE) {
        return fail(cpu, "Range change requires the idle owner and aligned guest pages");
    }
    if (replace) {
        backing = find_backing(cpu, backing_id);
        if (!backing || offset % TARGET_PAGE_SIZE ||
            offset > backing->size || size > backing->size - offset ||
            (permissions & ~7u)) {
            return fail(cpu, "Invalid replacement backing extent or permissions");
        }
    }
    end = address + size;
    /* PROT_NONE is owned memory, not a hole. Preflight every covered alias. */
    for (uint64_t cursor = address; cursor < end; ) {
        AnyPS5QemuRange *range = find_range(cpu, cursor, 1);
        if (!range) {
            return fail(cpu, "Range change includes unmapped guest memory");
        }
        cursor = MIN(end, range->address + range->size);
    }
    for (size_t i = 0; i < cpu->range_count; i++) {
        AnyPS5QemuRange *range = cpu->ranges[i];
        uint64_t range_end = range->address + range->size;
        if (address >= range_end || range->address >= end) {
            needed++;
        } else {
            needed += range->address < address;
            needed += range_end > end;
        }
    }
    if (needed > ANYPS5_MAX_RANGES) {
        return fail(cpu, "Range change exceeds guest alias capacity");
    }
    /* Allocate metadata before touching MemoryRegions or backing references. */
    for (size_t i = 0; i < cpu->range_count; i++) {
        AnyPS5QemuRange *range = cpu->ranges[i];
        uint64_t range_end = range->address + range->size;
        if (address >= range_end || range->address >= end) {
            updated[count] = range;
            added[count++] = false;
            continue;
        }
        removed[removed_count++] = range;
        if (range->address < address) {
            updated[count] = retain_fragment(range, range->address,
                                              address - range->address);
            physical_offsets[count] = range->region.alias_offset;
            added[count++] = true;
        }
        if (range_end > end) {
            updated[count] = retain_fragment(range, end, range_end - end);
            physical_offsets[count] = range->region.alias_offset +
                                      end - range->address;
            added[count++] = true;
        }
    }
    if (replace) {
        AnyPS5QemuProtection p = { 0, size, permissions };
        AnyPS5QemuRange *range = g_new0(AnyPS5QemuRange, 1);
        range->address = address;
        range->size = size;
        range->backing = backing;
        range->protections = g_array_new(false, false, sizeof(p));
        g_array_append_val(range->protections, p);
        updated[count] = range;
        physical_offsets[count] = offset;
        added[count++] = true;
    }
    cs = CPU(cpu->x86);
    bql_lock();
    halt_cond = cs->halt_cond;
    cs->halt_cond = NULL;
    memory_region_transaction_begin();
    for (size_t i = 0; i < removed_count; i++) {
        memory_region_del_subregion(get_system_memory(), &removed[i]->region);
        removed[i]->backing->aliases--;
    }
    for (size_t i = 0; i < count; i++) {
        AnyPS5QemuRange *range = updated[i];
        if (!added[i]) {
            continue;
        }
        memory_region_init_alias(&range->region, OBJECT(cpu->x86),
                                 "anyps5-alias", &range->backing->region,
                                 physical_offsets[i], range->size);
        memory_region_add_subregion(get_system_memory(), range->address,
                                     &range->region);
        range->backing->aliases++;
    }
    memcpy(cpu->ranges, updated, count * sizeof(updated[0]));
    cpu->range_count = count;
    memory_region_transaction_commit();
    for (size_t i = 0; i < removed_count; i++) {
        object_unparent(OBJECT(&removed[i]->region));
    }
    size_t remaining_gates = 0;
    for (size_t i = 0; i < cpu->gate_count; i++) {
        if (cpu->gates[i].address >= address &&
            cpu->gates[i].address - address < size) {
            continue;
        }
        cpu->gates[remaining_gates++] = cpu->gates[i];
    }
    cpu->gate_count = remaining_gates;
    cs->halt_cond = halt_cond;
    tlb_flush(cs);
    tb_flush(cs);
    bql_unlock();
    /* Old FlatViews can refer to the embedded regions until RCU quiesces. */
    drain_call_rcu();
    for (size_t i = 0; i < removed_count; i++) {
        g_array_free(removed[i]->protections, true);
        g_free(removed[i]);
    }
    for (size_t i = 0; i < cpu->backing_count; ) {
        AnyPS5QemuBacking *old = cpu->backings[i];
        if (old->automatic && !old->aliases) {
            int result = anyps5_qemu_cpu_release_backing(cpu, old->id);
            g_assert(result == 0);
        } else {
            i++;
        }
    }
    return 0;
}

int anyps5_qemu_cpu_unmap_range(AnyPS5QemuCpu *cpu, uint64_t address, size_t size)
{
    return change_guest_range(cpu, address, size, false, 0, 0, 0);
}

int anyps5_qemu_cpu_replace_alias(AnyPS5QemuCpu *cpu, uint64_t address,
                                uint64_t backing_id, size_t offset, size_t size,
                                unsigned permissions)
{
    return change_guest_range(cpu, address, size, true, backing_id, offset,
                              permissions);
}

int anyps5_qemu_cpu_protect_fragment(AnyPS5QemuCpu *cpu, uint64_t address,
                                   size_t size, unsigned permissions)
{
    AnyPS5QemuRange *range;
    GArray *updated;
    size_t page_first, page_last, first, last, cursor;
    uint64_t page;

    if (!on_owner(cpu)) {
        return fail(NULL, "Data fragment protection requires its CPU owner");
    }
    if (cpu->running || !size || address >= 0x800000000000ULL ||
        size > 0x800000000000ULL - address ||
        size > TARGET_PAGE_SIZE - (address & ~TARGET_PAGE_MASK) ||
        (permissions & ~(ANYPS5_QEMU_READ | ANYPS5_QEMU_WRITE))) {
        return fail(cpu, "Data fragment protection requires one mapped page and data permissions");
    }
    page = address & TARGET_PAGE_MASK;
    range = find_range(cpu, page, TARGET_PAGE_SIZE);
    if (!range) {
        return fail(cpu, "Data fragment protection requires a complete mapped page");
    }
    page_first = page - range->address;
    page_last = page_first + TARGET_PAGE_SIZE;
    cursor = page_first;
    /* Preflight the whole page, including gaps and executable neighbors. */
    for (size_t i = 0; i < range->protections->len; i++) {
        AnyPS5QemuProtection *p = &g_array_index(range->protections,
                                               AnyPS5QemuProtection, i);
        if (p->offset >= page_last || page_first >= p->offset + p->size) {
            continue;
        }
        if (p->offset > cursor || (p->permissions & ANYPS5_QEMU_EXECUTE)) {
            return fail(cpu, "Data fragment page contains a gap or executable bytes");
        }
        cursor = MIN(page_last, p->offset + p->size);
    }
    if (cursor != page_last) {
        return fail(cpu, "Data fragment page has incomplete protection coverage");
    }
    first = address - range->address;
    last = first + size;
    updated = g_array_new(false, false, sizeof(AnyPS5QemuProtection));
    for (size_t i = 0; i < range->protections->len; i++) {
        AnyPS5QemuProtection p = g_array_index(range->protections,
                                              AnyPS5QemuProtection, i);
        size_t p_end = p.offset + p.size;
        if (p.offset >= last || first >= p_end) {
            append_protection(updated, p);
            continue;
        }
        size_t overlap_first = MAX(first, p.offset);
        size_t overlap_last = MIN(last, p_end);
        append_protection(updated, (AnyPS5QemuProtection) {
            p.offset, overlap_first - p.offset, p.permissions });
        append_protection(updated, (AnyPS5QemuProtection) {
            overlap_first, overlap_last - overlap_first, permissions });
        append_protection(updated, (AnyPS5QemuProtection) {
            overlap_last, p_end - overlap_last, p.permissions });
    }
    GArray *old = range->protections;
    range->protections = updated;
    g_array_free(old, true);
    return anyps5_qemu_cpu_invalidate(cpu);
}

int anyps5_qemu_cpu_protect_range(AnyPS5QemuCpu *cpu, uint64_t address,
                                size_t size, unsigned permissions)
{
    uint64_t end;
    if (!on_owner(cpu) || cpu->running || !size ||
        address >= 0x800000000000ULL || size > 0x800000000000ULL - address ||
        address % TARGET_PAGE_SIZE || size % TARGET_PAGE_SIZE ||
        (permissions & ~7u)) {
        return fail(cpu, "Protect requires the idle owner and aligned guest pages");
    }
    end = address + size;
    /* Reject gaps before changing any protection or cached translation. */
    for (uint64_t cursor = address; cursor < end; ) {
        AnyPS5QemuRange *range = find_range(cpu, cursor, 1);
        if (!range) {
            return fail(cpu, "Protection range includes unmapped guest memory");
        }
        cursor = MIN(end, range->address + range->size);
    }
    for (size_t i = 0; i < cpu->range_count; i++) {
        AnyPS5QemuRange *range = cpu->ranges[i];
        if (address >= range->address + range->size || range->address >= end) {
            continue;
        }
        size_t first = MAX(address, range->address) - range->address;
        size_t last = MIN(end, range->address + range->size) - range->address;
        GArray *updated = g_array_new(false, false, sizeof(AnyPS5QemuProtection));
        for (size_t j = 0; j < range->protections->len; j++) {
            AnyPS5QemuProtection p = g_array_index(range->protections,
                                                  AnyPS5QemuProtection, j);
            size_t p_end = p.offset + p.size;
            if (p.offset >= last || first >= p_end) {
                append_protection(updated, p);
                continue;
            }
            size_t overlap_first = MAX(first, p.offset);
            size_t overlap_last = MIN(last, p_end);
            append_protection(updated, (AnyPS5QemuProtection) {
                p.offset, overlap_first - p.offset, p.permissions });
            append_protection(updated, (AnyPS5QemuProtection) {
                overlap_first, overlap_last - overlap_first, permissions });
            append_protection(updated, (AnyPS5QemuProtection) {
                overlap_last, p_end - overlap_last, p.permissions });
        }
        g_array_free(range->protections, true);
        range->protections = updated;
    }
    return anyps5_qemu_cpu_invalidate(cpu);
}

int anyps5_qemu_cpu_protect(AnyPS5QemuCpu *cpu, uint64_t address,
                          unsigned permissions)
{
    if (!on_owner(cpu) || cpu->running || (permissions & ~7u)) {
        return fail(cpu, "Protect requires the idle owner and valid permissions");
    }
    for (size_t i = 0; i < cpu->range_count; i++) {
        if (cpu->ranges[i]->address == address) {
            return anyps5_qemu_cpu_protect_range(cpu, address,
                                               cpu->ranges[i]->size, permissions);
        }
    }
    return fail(cpu, "Protect requires an existing range base");
}

int anyps5_qemu_cpu_get(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg,
                       uint64_t *value)
{
    CPUX86State *env;
    if (!on_owner(cpu) || cpu->running || !value) {
        return fail(cpu, "Register access requires the idle owner thread");
    }
    env = &cpu->x86->env;
    if (reg >= ANYPS5_QEMU_RAX && reg <= ANYPS5_QEMU_R15) {
        *value = env->regs[reg];
    } else if (reg == ANYPS5_QEMU_RIP) {
        *value = env->eip;
    } else if (reg == ANYPS5_QEMU_RFLAGS) {
        *value = env->eflags;
    } else if (reg == ANYPS5_QEMU_FS_BASE) {
        *value = env->segs[R_FS].base;
    } else if (reg == ANYPS5_QEMU_GS_BASE) {
        *value = env->segs[R_GS].base;
    } else {
        return fail(cpu, "Unsupported register");
    }
    return 0;
}

int anyps5_qemu_cpu_set(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg,
                       uint64_t value)
{
    CPUX86State *env;
    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Register access requires the idle owner thread");
    }
    env = &cpu->x86->env;
    if (reg >= ANYPS5_QEMU_RAX && reg <= ANYPS5_QEMU_R15) {
        env->regs[reg] = value;
    } else if (reg == ANYPS5_QEMU_RIP) {
        env->eip = value;
    } else if (reg == ANYPS5_QEMU_RFLAGS && !(value & ~0xcd7ULL)) {
        env->eflags = value | 2;
    } else if (reg == ANYPS5_QEMU_FS_BASE) {
        env->segs[R_FS].base = value;
    } else if (reg == ANYPS5_QEMU_GS_BASE) {
        env->segs[R_GS].base = value;
    } else {
        return fail(cpu, "Unsupported register or flag state");
    }
    return 0;
}

int anyps5_qemu_cpu_get_ymm(AnyPS5QemuCpu *cpu, unsigned reg, void *value)
{
    if (!on_owner(cpu) || cpu->running || reg >= 16 || !value) {
        return fail(cpu, "Invalid vector register access");
    }
    memcpy(value, &cpu->x86->env.xmm_regs[reg], 32);
    return 0;
}

int anyps5_qemu_cpu_set_ymm(AnyPS5QemuCpu *cpu, unsigned reg, const void *value)
{
    if (!on_owner(cpu) || cpu->running || reg >= 16 || !value) {
        return fail(cpu, "Invalid vector register access");
    }
    memcpy(&cpu->x86->env.xmm_regs[reg], value, 32);
    return 0;
}

int anyps5_qemu_cpu_add_gate(AnyPS5QemuCpu *cpu, uint64_t address, uint64_t id)
{
    size_t i;
    AnyPS5QemuRange *range;
    if (!on_owner(cpu) || cpu->running || cpu->gate_count == ANYPS5_MAX_GATES) {
        return fail(cpu, "Host gates require the idle owner thread");
    }
    range = find_range(cpu, address, 1);
    if (!range || !(range_permissions(range, address, 1) & ANYPS5_QEMU_EXECUTE)) {
        return fail(cpu, "Host gate must occupy executable guest memory");
    }
    for (i = 0; i < cpu->gate_count; i++) {
        if (cpu->gates[i].address == address) {
            return fail(cpu, "Duplicate host gate");
        }
    }
    cpu->gates[cpu->gate_count++] = (AnyPS5QemuGate) { address, id };
    return 0;
}

static int run_cpu(AnyPS5QemuCpu *cpu, uint64_t instruction_budget,
                   bool use_until, uint64_t until, AnyPS5QemuRunResult *result)
{
    CPUState *cs;
    uint64_t count = 0;
    size_t i;

    if (!on_owner(cpu) || cpu->running || !result || !instruction_budget) {
        return fail(cpu, "Run requires the idle owner and a positive budget");
    }
    cs = CPU(cpu->x86);
    memset(&cpu->stopped, 0, sizeof(cpu->stopped));
    cpu->pending = false;
    cpu->running = true;
    qatomic_set(&cs->exit_request, false);
    cpu->stopped.reason = ANYPS5_QEMU_BUDGET;
    while (count < instruction_budget) {
        int reason;
        AnyPS5QemuRange *range;
        if (qatomic_read(&cpu->requested_stop)) {
            cpu->stopped.reason = ANYPS5_QEMU_REQUESTED_STOP;
            break;
        }
        if (use_until && cpu->x86->env.eip == until) {
            cpu->stopped.reason = ANYPS5_QEMU_STOP_ADDRESS;
            break;
        }
        range = find_range(cpu, cpu->x86->env.eip, 1);
        if (!range || !(range_permissions(range, cpu->x86->env.eip, 1) & ANYPS5_QEMU_EXECUTE)) {
            save_stop(cpu, ANYPS5_QEMU_FAULT, cpu->x86->env.eip,
                      EXCP0E_PAGE, PG_ERROR_I_D_MASK | PG_ERROR_U_MASK |
                      (range ? PG_ERROR_P_MASK : 0));
            break;
        }
        for (i = 0; i < cpu->gate_count; i++) {
            if (cpu->gates[i].address == cpu->x86->env.eip) {
                cpu->stopped.reason = ANYPS5_QEMU_HOST_GATE;
                cpu->stopped.gate = cpu->gates[i].id;
                cpu->pending = true;
                break;
            }
        }
        if (cpu->pending) {
            break;
        }
        if (application_service_instruction(cpu, cpu->x86->env.eip)) {
            save_stop(cpu, ANYPS5_QEMU_UNSUPPORTED, 0, EXCP0D_GPF, 0);
            break;
        }
        cs->exception_index = -1;
        cpu_exec_start(cs);
        reason = cpu_exec(cs);
        cpu_exec_end(cs);
        if (cpu->pending) {
            if (cpu->stopped.reason == ANYPS5_QEMU_SYSCALL) {
                count++;
            }
            break;
        }
        if (reason == EXCP_INTERRUPT) {
            /* Pair with stop's publication before cpu_exit sets exit_request. */
            smp_rmb();
            if (qatomic_read(&cpu->requested_stop)) {
                /* An interrupted iteration has not retired an instruction. */
                cpu->stopped.reason = ANYPS5_QEMU_REQUESTED_STOP;
                break;
            }
        }
        if (reason != EXCP_DEBUG) {
            save_stop(cpu, ANYPS5_QEMU_UNSUPPORTED, 0, reason, 0);
            break;
        }
        count++;
    }
    cpu->running = false;
    if (use_until && cpu->stopped.reason == ANYPS5_QEMU_BUDGET &&
        cpu->x86->env.eip == until) {
        cpu->stopped.reason = ANYPS5_QEMU_STOP_ADDRESS;
    }
    cpu->stopped.instructions = count;
    cpu->stopped.rip = cpu->x86->env.eip;
    *result = cpu->stopped;
    return 0;
}

int anyps5_qemu_cpu_run(AnyPS5QemuCpu *cpu, uint64_t instruction_budget,
                       AnyPS5QemuRunResult *result)
{
    return run_cpu(cpu, instruction_budget, false, 0, result);
}

int anyps5_qemu_cpu_run_until(AnyPS5QemuCpu *cpu, uint64_t instruction_budget,
                            uint64_t until, AnyPS5QemuRunResult *result)
{
    if (until >= 0x800000000000ULL) {
        return fail(cpu, "Stop address must be lower canonical guest memory");
    }
    return run_cpu(cpu, instruction_budget, true, until, result);
}

void anyps5_qemu_cpu_stop(AnyPS5QemuCpu *cpu)
{
    if (cpu && active_cpu == cpu) {
        qatomic_set(&cpu->requested_stop, true);
        /* Publish the bridge reason before QEMU can observe exit_request. */
        smp_wmb();
        cpu_exit(CPU(cpu->x86));
    }
}

int anyps5_qemu_cpu_clear_stop(AnyPS5QemuCpu *cpu)
{
    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Clearing stop requires the idle owner thread");
    }
    qatomic_set(&cpu->requested_stop, false);
    qatomic_set(&CPU(cpu->x86)->exit_request, false);
    return 0;
}

const char *anyps5_qemu_cpu_error(AnyPS5QemuCpu *cpu)
{
    return cpu ? cpu->error : "No CPU bridge context";
}

int anyps5_qemu_cpu_destroy(AnyPS5QemuCpu *cpu)
{
    CPUState *cs;
    QemuCond *halt_cond;
    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Destroy requires the idle owner thread");
    }
    while (cpu->range_count) {
        if (anyps5_qemu_cpu_unmap(cpu, cpu->ranges[0]->address)) {
            return -1;
        }
    }
    while (cpu->backing_count) {
        if (anyps5_qemu_cpu_release_backing(cpu, cpu->backings[0]->id)) {
            return -1;
        }
    }
    while (cpu->contexts) {
        AnyPS5QemuContext *context = cpu->contexts;
        cpu->contexts = context->next;
        g_free(context->state);
        g_free(context);
    }
    cs = CPU(cpu->x86);
    bql_lock();
    cpu_list_remove(cs);
    /* Listener unregister must not queue work on a nonexistent vCPU loop. */
    halt_cond = cs->halt_cond;
    cs->halt_cond = NULL;
    cpu_destroy_address_spaces(cs);
    cs->halt_cond = halt_cond;
    tcg_exec_unrealizefn(cs);
    if (current_cpu == cs) {
        current_cpu = NULL;
    }
    /* Reclaim address-space and TCG callbacks while their CPU owner is alive. */
    drain_call_rcu();
    /* The CPU's strong QOM memory link releases its reference on finalize. */
    object_unref(OBJECT(cpu->x86));
    active_cpu = NULL;
    bql_unlock();
    drain_call_rcu();
    g_free(cpu);
    return 0;
}
