#include "qemu/osdep.h"
#include "qemu/anyps5-cpu.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
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

typedef struct AnyPS5QemuRange {
    uint64_t address;
    size_t size;
    unsigned permissions;
    void *backing;
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
    AnyPS5QemuGate gates[ANYPS5_MAX_GATES];
    size_t gate_count;
    AnyPS5QemuRunResult stopped;
    bool pending;
    bool running;
    bool requested_stop;
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

static bool bridge_tlb_fill(CPUState *cs, vaddr address, int size,
                            MMUAccessType access_type, int mmu_idx,
                            bool probe, uintptr_t retaddr)
{
    AnyPS5QemuCpu *cpu = active_cpu;
    AnyPS5QemuRange *range;
    unsigned permission;

    g_assert(cpu && CPU(cpu->x86) == cs);
    permission = access_type == MMU_INST_FETCH ? ANYPS5_QEMU_EXECUTE :
                 access_type == MMU_DATA_STORE ? ANYPS5_QEMU_WRITE :
                                                ANYPS5_QEMU_READ;
    range = address <= 0x7fffffffffffULL ?
            find_range(cpu, address, size > 0 ? size : 1) : NULL;
    if (!range || !(range->permissions & permission)) {
        if (probe) {
            return false;
        }
        save_stop(cpu, ANYPS5_QEMU_FAULT, address, EXCP0E_PAGE,
                  (range ? PG_ERROR_P_MASK : 0) | PG_ERROR_U_MASK |
                  (access_type == MMU_DATA_STORE ? PG_ERROR_W_MASK : 0) |
                  (access_type == MMU_INST_FETCH ? PG_ERROR_I_D_MASK : 0));
        cs->exception_index = ANYPS5_EXCP_STOP;
        cpu_loop_exit_restore(cs, retaddr);
    }
    tlb_set_page(cs, address & TARGET_PAGE_MASK, address & TARGET_PAGE_MASK,
                 range->permissions, mmu_idx, TARGET_PAGE_SIZE);
    return true;
}

static void bridge_interrupt(CPUState *cs)
{
    AnyPS5QemuCpu *cpu = active_cpu;
    CPUX86State *env = cpu_env(cs);

    save_stop(cpu, ANYPS5_QEMU_UNSUPPORTED, env->cr[2],
              cs->exception_index, env->error_code);
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
    cpu_set_fpuc(env, 0x37f);
    cpu_set_mxcsr(env, 0x1f80);
    bql_unlock();
    return cpu;
}

int anyps5_qemu_cpu_map_borrowed(AnyPS5QemuCpu *cpu, uint64_t address,
                               void *backing, size_t size, unsigned permissions)
{
    AnyPS5QemuRange *range;
    size_t i;
    size_t host_page = qemu_real_host_page_size();
    QemuCond *halt_cond;
    CPUState *cs;

    if (!on_owner(cpu) || cpu->running) {
        return fail(cpu, "Mapping requires the idle owner thread");
    }
    if (!backing || !size || address >= 0x800000000000ULL ||
        size > 0x800000000000ULL - address ||
        address % TARGET_PAGE_SIZE || size % host_page ||
        (uintptr_t)backing % host_page || (permissions & ~7u) ||
        cpu->range_count == ANYPS5_MAX_RANGES) {
        return fail(cpu, "Invalid mapping or unsupported host-page alignment");
    }
    for (i = 0; i < cpu->range_count; i++) {
        range = cpu->ranges[i];
        if (address < range->address + range->size &&
            range->address < address + size) {
            return fail(cpu, "Guest mappings overlap");
        }
    }
    range = g_new0(AnyPS5QemuRange, 1);
    range->address = address;
    range->size = size;
    range->permissions = permissions;
    range->backing = backing;
    cs = CPU(cpu->x86);
    bql_lock();
    halt_cond = cs->halt_cond;
    cs->halt_cond = NULL;
    memory_region_init_ram_ptr(&range->region, OBJECT(cpu->x86),
                               "anyps5-borrowed", size, backing);
    memory_region_add_subregion(get_system_memory(), address, &range->region);
    cpu->ranges[cpu->range_count++] = range;
    cs->halt_cond = halt_cond;
    tlb_flush(cs);
    bql_unlock();
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
        bql_unlock();
        /* FlatView callbacks still dereference embedded MemoryRegion storage. */
        drain_call_rcu();
        g_free(range);
        return 0;
    }
    return fail(cpu, "Unmapping requires an existing range base");
}

int anyps5_qemu_cpu_protect(AnyPS5QemuCpu *cpu, uint64_t address,
                          unsigned permissions)
{
    size_t i;
    if (!on_owner(cpu) || cpu->running || (permissions & ~7u)) {
        return fail(cpu, "Protect requires the idle owner and valid permissions");
    }
    for (i = 0; i < cpu->range_count; i++) {
        if (cpu->ranges[i]->address == address) {
            cpu->ranges[i]->permissions = permissions;
            bql_lock();
            tlb_flush(CPU(cpu->x86));
            tb_flush(CPU(cpu->x86));
            bql_unlock();
            return 0;
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
    if (!range || !(range->permissions & ANYPS5_QEMU_EXECUTE)) {
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

int anyps5_qemu_cpu_run(AnyPS5QemuCpu *cpu, uint64_t instruction_budget,
                       AnyPS5QemuRunResult *result)
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
        range = find_range(cpu, cpu->x86->env.eip, 1);
        if (!range || !(range->permissions & ANYPS5_QEMU_EXECUTE)) {
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
        if (reason != EXCP_DEBUG) {
            save_stop(cpu, ANYPS5_QEMU_UNSUPPORTED, 0, reason, 0);
            break;
        }
        count++;
    }
    cpu->running = false;
    cpu->stopped.instructions = count;
    cpu->stopped.rip = cpu->x86->env.eip;
    *result = cpu->stopped;
    return 0;
}

void anyps5_qemu_cpu_stop(AnyPS5QemuCpu *cpu)
{
    if (cpu && active_cpu == cpu) {
        qatomic_set(&cpu->requested_stop, true);
        cpu_exit(CPU(cpu->x86));
    }
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
