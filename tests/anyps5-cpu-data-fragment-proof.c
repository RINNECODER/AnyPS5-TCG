#include "qemu/anyps5-cpu.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum Fixture {
    LOAD1, LOAD2, LOAD4, LOAD8, LOAD16, LOAD32,
    STORE1, STORE2, STORE4, STORE8, STORE16, STORE32,
    PREFIX_LOAD, PREFIX_STORE, LOCKED_ADD, CMPXCHG16, FLD_ONE, FST_POP,
    FXSAVE, MASK_LOAD, MASK_STORE, GATHER, REP_COPY, GATE, READ_THEN_STORE,
    FNINIT, MASK_LOAD_PS128, MASK_ALIAS_PS128, MASK_ALIAS_PS256,
    MASK_LOAD_PD128, MASK_ALIAS_PD128, MASK_LOAD_PD256, MASK_ALIAS_PD256,
    MASK_LOAD_D128, MASK_ALIAS_D128, MASK_LOAD_D256, MASK_ALIAS_D256,
    MASK_LOAD_Q128, MASK_ALIAS_Q128, MASK_LOAD_Q256, MASK_ALIAS_Q256,
    FIXTURE_COUNT
};

enum { PAGE = 4096, FLAGS = 0x803 };
static const uint64_t code_base = UINT64_C(0x1000000);
static const uint64_t data_base = UINT64_C(0x200000000);
static const uint64_t alias_base = UINT64_C(0x300000000);
static const uint64_t accumulator = UINT64_C(0x8877665544332211);

typedef struct Proof {
    AnyPS5QemuCpu *cpu;
    uint8_t *code, *data, *expected;
    size_t allocation;
    uint32_t offsets[FIXTURE_COUNT], lengths[FIXTURE_COUNT];
    uint8_t vector[32];
    enum Fixture last_fixture, prior_fixture;
    AnyPS5QemuRunResult last_result, prior_result;
} Proof;

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void api(Proof *p, int result, const char *message)
{
    if (result != 0) {
        fprintf(stderr, "FAIL: %s: %s\n", message,
                anyps5_qemu_cpu_error(p->cpu));
        exit(1);
    }
}

static void set(Proof *p, enum AnyPS5QemuRegister reg, uint64_t value)
{
    api(p, anyps5_qemu_cpu_set(p->cpu, reg, value), "set register");
}

static uint64_t get(Proof *p, enum AnyPS5QemuRegister reg)
{
    uint64_t value;
    api(p, anyps5_qemu_cpu_get(p->cpu, reg, &value), "get register");
    return value;
}

static uint64_t little(const uint8_t *bytes, size_t size)
{
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i) {
        value |= (uint64_t)bytes[i] << (8 * i);
    }
    return value;
}

static void put32(uint8_t *bytes, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = value >> (8 * i);
    }
}

static void seed(Proof *p)
{
    for (size_t i = 0; i < p->allocation; ++i) {
        p->data[i] = (uint8_t)(i * 37 + (i >> 8) * 13 + 0x51);
    }
    memcpy(p->expected, p->data, p->allocation);
    api(p, anyps5_qemu_cpu_protect_range(p->cpu, data_base,
                                       4 * PAGE, 3), "restore data permissions");
    api(p, anyps5_qemu_cpu_protect_range(p->cpu, alias_base,
                                       PAGE, 3), "restore alias permissions");
    set(p, ANYPS5_QEMU_RAX, accumulator);
    set(p, ANYPS5_QEMU_RFLAGS, FLAGS);
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 0, p->vector), "seed YMM0");
}

static void fragment(Proof *p, size_t offset, size_t size, unsigned permissions)
{
    api(p, anyps5_qemu_cpu_protect_fragment(p->cpu, data_base + offset,
                                          size, permissions), "protect fragment");
}

static uint64_t start(Proof *p, enum Fixture fixture)
{
    return code_base + p->offsets[fixture];
}

static AnyPS5QemuRunResult execute(Proof *p, enum Fixture fixture)
{
    AnyPS5QemuRunResult result;
    p->prior_fixture = p->last_fixture;
    p->prior_result = p->last_result;
    p->last_fixture = fixture;
    set(p, ANYPS5_QEMU_RIP, start(p, fixture));
    api(p, anyps5_qemu_cpu_run_until(p->cpu, 64,
                                   start(p, fixture) + p->lengths[fixture],
                                   &result), "execute actual x86 fixture");
    p->last_result = result;
    return result;
}

static void completed(Proof *p, enum Fixture fixture, AnyPS5QemuRunResult result)
{
    uint64_t observed_pc = get(p, ANYPS5_QEMU_RIP);
    uint64_t expected_pc = start(p, fixture) + p->lengths[fixture];
    if (result.reason != ANYPS5_QEMU_STOP_ADDRESS || result.rip != expected_pc ||
        observed_pc != result.rip) {
        fprintf(stderr, "STOP DETAIL: fixture=%u start=%llx expected=%llx "
                "pc=%llx register_pc=%llx reason=%u vector=%u address=%llx "
                "error=%x instructions=%llu\n", fixture,
                (unsigned long long)start(p, fixture),
                (unsigned long long)expected_pc, (unsigned long long)result.rip,
                (unsigned long long)observed_pc, result.reason, result.vector,
                (unsigned long long)result.address, result.error_code,
                (unsigned long long)result.instructions);
    }
    require(result.reason == ANYPS5_QEMU_STOP_ADDRESS &&
            result.rip == start(p, fixture) + p->lengths[fixture] &&
            get(p, ANYPS5_QEMU_RIP) == result.rip,
            "actual instruction reaches independently bounded next PC");
}

static void fault(Proof *p, enum Fixture fixture, AnyPS5QemuRunResult result,
                  uint64_t denied, size_t size, unsigned write)
{
    if (result.reason != ANYPS5_QEMU_FAULT || result.vector != 14 ||
        result.rip != start(p, fixture) ||
        get(p, ANYPS5_QEMU_RIP) != start(p, fixture) ||
        result.address < denied || result.address - denied >= size ||
        ((result.error_code >> 1) & 1) != write) {
        fprintf(stderr, "FAIL: precise fragment fault fixture=%u reason=%u "
                "vector=%u pc=%llx address=%llx error=%x\n", fixture,
                result.reason, result.vector, (unsigned long long)result.rip,
                (unsigned long long)result.address, result.error_code);
        exit(1);
    }
}

static void unchanged(Proof *p)
{
    require(!memcmp(p->data, p->expected, p->allocation),
            "entire independently seeded backing including guards is unchanged");
}

static void unchanged_flags(Proof *p)
{
    static const char *names[] = {
        "LOAD1", "LOAD2", "LOAD4", "LOAD8", "LOAD16", "LOAD32",
        "STORE1", "STORE2", "STORE4", "STORE8", "STORE16", "STORE32",
        "PREFIX_LOAD", "PREFIX_STORE", "LOCKED_ADD", "CMPXCHG16", "FLD_ONE",
        "FST_POP", "FXSAVE", "MASK_LOAD", "MASK_STORE", "GATHER", "REP_COPY",
        "GATE", "READ_THEN_STORE", "FNINIT", "MASK_LOAD_PS128", "MASK_ALIAS_PS128",
        "MASK_ALIAS_PS256", "MASK_LOAD_PD128", "MASK_ALIAS_PD128", "MASK_LOAD_PD256",
        "MASK_ALIAS_PD256", "MASK_LOAD_D128", "MASK_ALIAS_D128", "MASK_LOAD_D256",
        "MASK_ALIAS_D256", "MASK_LOAD_Q128", "MASK_ALIAS_Q128", "MASK_LOAD_Q256",
        "MASK_ALIAS_Q256"
    };
    uint64_t flags = get(p, ANYPS5_QEMU_RFLAGS);
    if (flags != FLAGS) {
        fprintf(stderr, "FLAGS DETAIL: fixture=%u name=%s rip=%llx flags=%llx "
                "expected=%x reason=%u vector=%u address=%llx error=%x instructions=%llu "
                "prior_fixture=%u prior_reason=%u prior_vector=%u prior_address=%llx\n",
                p->last_fixture, names[p->last_fixture],
                (unsigned long long)get(p, ANYPS5_QEMU_RIP),
                (unsigned long long)flags, FLAGS, p->last_result.reason,
                p->last_result.vector, (unsigned long long)p->last_result.address,
                p->last_result.error_code, (unsigned long long)p->last_result.instructions,
                p->prior_fixture, p->prior_result.reason, p->prior_result.vector,
                (unsigned long long)p->prior_result.address);
    }
    require(get(p, ANYPS5_QEMU_RFLAGS) == FLAGS,
            "non-arithmetic or denied operation preserves independently seeded flags");
}

static void data_permissions(Proof *p)
{
    seed(p);
    fragment(p, 256, 1, 2);
    set(p, ANYPS5_QEMU_RDI, data_base + 256);
    completed(p, STORE1, execute(p, STORE1));
    p->expected[256] = (uint8_t)accumulator;
    unchanged(p);
    fault(p, LOAD1, execute(p, LOAD1), data_base + 256, 1, 0);
    require(get(p, ANYPS5_QEMU_RAX) == accumulator,
            "WRITE-only fragment permits stores but preserves register on denied read");
    unchanged_flags(p);
    fragment(p, 256, 1, 1);
    completed(p, LOAD1, execute(p, LOAD1));
    fault(p, STORE1, execute(p, STORE1), data_base + 256, 1, 1);
    unchanged(p);
    unchanged_flags(p);
    fragment(p, 256, 1, 0);
    fault(p, LOAD1, execute(p, LOAD1), data_base + 256, 1, 0);
    fault(p, STORE1, execute(p, STORE1), data_base + 256, 1, 1);
    unchanged(p);
    fragment(p, 256, 1, 3);
    completed(p, READ_THEN_STORE, execute(p, READ_THEN_STORE));
    unchanged(p);
    unchanged_flags(p);
}

static void cache_prefix(Proof *p)
{
    seed(p);
    fragment(p, 128, 1, 0);
    set(p, ANYPS5_QEMU_RDI, data_base + 64);
    AnyPS5QemuRunResult r = execute(p, PREFIX_LOAD);
    require(r.reason == ANYPS5_QEMU_FAULT && r.vector == 14 &&
            r.address == data_base + 128 && r.instructions == 1 &&
            r.rip == start(p, PREFIX_LOAD) + 2 &&
            get(p, ANYPS5_QEMU_RIP) == r.rip &&
            get(p, ANYPS5_QEMU_RAX) ==
                ((accumulator & ~UINT64_C(255)) | p->expected[64]),
            "same-page allowed read cannot cache permission for denied next byte");
    unchanged(p);
    unchanged_flags(p);
    seed(p);
    fragment(p, 128, 1, 1);
    set(p, ANYPS5_QEMU_RDI, data_base + 64);
    r = execute(p, PREFIX_STORE);
    p->expected[64] = (uint8_t)accumulator;
    require(r.reason == ANYPS5_QEMU_FAULT && r.vector == 14 &&
            r.address == data_base + 128 && r.instructions == 1 &&
            r.rip == start(p, PREFIX_STORE) + 2 && (r.error_code & 2),
            "same-page allowed write cannot cache permission for denied next byte");
    unchanged(p);
    unchanged_flags(p);
}

static void widths(Proof *p)
{
    static const size_t sizes[] = {1, 2, 4, 8, 16, 32};
    for (unsigned width = 0; width < 6; ++width) {
        size_t size = sizes[width];
        enum Fixture load = LOAD1 + width, store = STORE1 + width;
        seed(p);
        set(p, ANYPS5_QEMU_RDI, data_base + 256);
        completed(p, load, execute(p, load));
        if (size <= 8) {
            uint64_t expected = little(p->expected + 256, size);
            if (size < 4) {
                expected |= accumulator & (UINT64_MAX << (size * 8));
            }
            require(get(p, ANYPS5_QEMU_RAX) == expected,
                    "successful scalar load obeys exact x86 destination width");
        } else {
            uint8_t observed[32], expected[32];
            memcpy(expected, p->vector, 32);
            memcpy(expected, p->expected + 256, size);
            api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read loaded YMM");
            require(!memcmp(observed, expected, 32),
                    "successful vector load preserves legacy SSE upper half");
        }
        unchanged(p);
        unchanged_flags(p);
        seed(p);
        set(p, ANYPS5_QEMU_RDI, data_base + 256);
        completed(p, store, execute(p, store));
        for (size_t i = 0; i < size; ++i) {
            p->expected[256 + i] = size <= 8 ? accumulator >> (i * 8) : p->vector[i];
        }
        unchanged(p);
        unchanged_flags(p);
        for (unsigned page_cross = 0; page_cross < 2; ++page_cross) {
            size_t boundary = page_cross ? PAGE : 512;
            size_t offset = boundary - (size > 1 ? size / 2 : 0);
            seed(p);
            fragment(p, boundary, size, 0);
            set(p, ANYPS5_QEMU_RDI, data_base + offset);
            AnyPS5QemuRunResult r = execute(p, load);
            fault(p, load, r, data_base + boundary, size, 0);
            require(r.instructions == 0 && get(p, ANYPS5_QEMU_RAX) == accumulator,
                    "denied load retires nothing and preserves accumulator");
            uint8_t observed[32];
            api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read denied vector");
            require(!memcmp(observed, p->vector, 32),
                    "denied vector load preserves complete destination");
            unchanged(p);
            unchanged_flags(p);
            seed(p);
            fragment(p, boundary, size, 1);
            set(p, ANYPS5_QEMU_RDI, data_base + offset);
            r = execute(p, store);
            fault(p, store, r, data_base + boundary, size, 1);
            require(r.instructions == 0 && get(p, ANYPS5_QEMU_RAX) == accumulator,
                    "denied normal store retires nothing and preserves source");
            unchanged(p);
            unchanged_flags(p);
        }
    }
}

static void ymm_preflight(Proof *p)
{
    seed(p);
    fragment(p, 528, 16, 0);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    AnyPS5QemuRunResult r = execute(p, STORE32);
    fault(p, STORE32, r, data_base + 528, 16, 1);
    require(r.instructions == 0, "split YMM store fault occurs before retirement");
    unchanged(p);
    unchanged_flags(p);
    uint8_t observed[32];
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read YMM store source");
    require(!memcmp(observed, p->vector, 32), "denied YMM store preserves source");
    fragment(p, 528, 16, 3);
    completed(p, STORE32, execute(p, STORE32));
    memcpy(p->expected + 512, p->vector, 32);
    unchanged(p);
}

static void locked(Proof *p)
{
    seed(p);
    fragment(p, 516, 4, 1);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    AnyPS5QemuRunResult r = execute(p, LOCKED_ADD);
    fault(p, LOCKED_ADD, r, data_base + 516, 4, 1);
    require(get(p, ANYPS5_QEMU_RAX) == accumulator && r.instructions == 0,
            "denied LOCK ADD preserves source and retirement state");
    unchanged(p);
    unchanged_flags(p);
    fragment(p, 516, 4, 3);
    uint64_t operand = little(p->expected + 512, 8);
    uint64_t sum = operand + accumulator;
    completed(p, LOCKED_ADD, execute(p, LOCKED_ADD));
    unsigned parity = 0;
    for (unsigned bit = 0; bit < 8; ++bit) {
        parity ^= (sum >> bit) & 1;
    }
    uint64_t flags = 2 | (sum < operand) | (!parity ? 4 : 0) |
                     (((operand ^ accumulator ^ sum) & 16) ? 16 : 0) |
                     (!sum ? 64 : 0) | ((sum >> 63) ? 128 : 0) |
                     ((~(operand ^ accumulator) & (operand ^ sum)) >> 63 ? 2048 : 0);
    require(get(p, ANYPS5_QEMU_RFLAGS) == flags,
            "successful LOCK ADD computes independent carry/parity/aux/zero/sign/overflow flags");
    for (unsigned i = 0; i < 8; ++i) {
        p->expected[512 + i] = sum >> (8 * i);
    }
    unchanged(p);
    seed(p);
    uint64_t low = little(p->expected + 512, 8);
    uint64_t high = little(p->expected + 520, 8);
    set(p, ANYPS5_QEMU_RAX, low);
    set(p, ANYPS5_QEMU_RDX, high);
    set(p, ANYPS5_QEMU_RBX, UINT64_C(0x1020304050607080));
    set(p, ANYPS5_QEMU_RCX, UINT64_C(0x90a0b0c0d0e0f000));
    fragment(p, 520, 8, 1);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    r = execute(p, CMPXCHG16);
    fault(p, CMPXCHG16, r, data_base + 520, 8, 1);
    require(r.instructions == 0 && get(p, ANYPS5_QEMU_RAX) == low &&
            get(p, ANYPS5_QEMU_RDX) == high &&
            get(p, ANYPS5_QEMU_RBX) == UINT64_C(0x1020304050607080) &&
            get(p, ANYPS5_QEMU_RCX) == UINT64_C(0x90a0b0c0d0e0f000),
            "denied CMPXCHG16B has no compare or replacement register effects");
    unchanged(p);
    unchanged_flags(p);
    fragment(p, 520, 8, 3);
    completed(p, CMPXCHG16, execute(p, CMPXCHG16));
    require(get(p, ANYPS5_QEMU_RFLAGS) == (FLAGS | 64),
            "successful CMPXCHG16B changes only ZF and sets it for matching comparison");
    for (unsigned i = 0; i < 8; ++i) {
        p->expected[512 + i] = UINT64_C(0x1020304050607080) >> (8 * i);
        p->expected[520 + i] = UINT64_C(0x90a0b0c0d0e0f000) >> (8 * i);
    }
    unchanged(p);
}

static void save_x87(Proof *p, uint8_t out[512])
{
    set(p, ANYPS5_QEMU_RDI, data_base + 2 * PAGE);
    completed(p, FXSAVE, execute(p, FXSAVE));
    memcpy(out, p->data + 2 * PAGE, 512);
    memcpy(p->expected + 2 * PAGE, out, 512);
}

static void x87(Proof *p)
{
    uint8_t before[512], after[512];
    seed(p);
    completed(p, FNINIT, execute(p, FNINIT));
    completed(p, FLD_ONE, execute(p, FLD_ONE));
    save_x87(p, before);
    require(little(before, 2) == 0x37f && ((little(before + 2, 2) >> 11) & 7) == 7 &&
            before[4] == 0x80 && little(before + 32, 8) == UINT64_C(0x8000000000000000) &&
            little(before + 40, 2) == 0x3fff,
            "actual FLD1 independently establishes TOP/tag and extended-precision one");
    fragment(p, 516, 4, 1);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    fault(p, FST_POP, execute(p, FST_POP), data_base + 516, 4, 1);
    unchanged(p);
    save_x87(p, after);
    require(little(before + 2, 2) == little(after + 2, 2) && before[4] == after[4] &&
            !memcmp(before + 32, after + 32, 10),
            "denied FSTP does not pop or change x87 value/status/tag");
    unchanged_flags(p);
    fragment(p, 516, 4, 3);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    completed(p, FST_POP, execute(p, FST_POP));
    require(little(p->data + 512, 8) == UINT64_C(0x3ff0000000000000),
            "restarted FSTP stores independently expected IEEE double one");
    memcpy(p->expected + 512, p->data + 512, 8);
    save_x87(p, after);
    require(((little(after + 2, 2) >> 11) & 7) == 0 && after[4] == 0,
            "successful FSTP pops the sole live x87 register");
    unchanged(p);
    fragment(p, 912, 16, 1);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    fault(p, FXSAVE, execute(p, FXSAVE), data_base + 912, 16, 1);
    unchanged(p);
    save_x87(p, before);
    require(((little(before + 2, 2) >> 11) & 7) == 0 && before[4] == 0,
            "FXSAVE denied tail preserves empty x87 stack");
}

static void aliases_and_rejections(Proof *p)
{
    seed(p);
    fragment(p, 512, 32, 0);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    fault(p, LOAD1, execute(p, LOAD1), data_base + 512, 32, 0);
    set(p, ANYPS5_QEMU_RDI, alias_base + 512);
    completed(p, STORE1, execute(p, STORE1));
    p->expected[512] = (uint8_t)accumulator;
    unchanged(p);
    completed(p, LOAD1, execute(p, LOAD1));
    require((get(p, ANYPS5_QEMU_RAX) & 255) == p->expected[512],
            "peer VA alias retains independent policy and sees shared physical write");
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    fault(p, LOAD1, execute(p, LOAD1), data_base + 512, 32, 0);
    static const struct { uint64_t offset; size_t size; unsigned permissions; } bad[] = {
        {64, 0, 3}, {PAGE - 1, 2, 3}, {4 * PAGE, 1, 3},
        {64, 1, 4}, {64, 1, 8}, {UINT64_MAX, 2, 3}
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        uint64_t address = bad[i].offset == UINT64_MAX ? UINT64_MAX : data_base + bad[i].offset;
        require(anyps5_qemu_cpu_protect_fragment(p->cpu, address, bad[i].size,
                                               bad[i].permissions) != 0,
                "malformed fragment request rejects before any policy mutation");
        set(p, ANYPS5_QEMU_RDI, data_base + 64);
        completed(p, READ_THEN_STORE, execute(p, READ_THEN_STORE));
        require((get(p, ANYPS5_QEMU_RAX) & 255) == p->expected[64],
                "rejected request retains prior readable/writable allowed prefix");
        set(p, ANYPS5_QEMU_RDI, data_base + 512);
        fault(p, LOAD1, execute(p, LOAD1), data_base + 512, 32, 0);
        unchanged(p);
    }
    require(anyps5_qemu_cpu_protect_fragment(p->cpu, start(p, GATE), 1, 0) != 0 &&
            anyps5_qemu_cpu_protect_fragment(p->cpu, code_base, PAGE, 0) != 0,
            "partial and whole executable pages both reject data-fragment API");
    api(p, anyps5_qemu_cpu_add_gate(p->cpu, start(p, GATE), 0x51), "register real guest gate");
    AnyPS5QemuRunResult r = execute(p, GATE);
    require(r.reason == ANYPS5_QEMU_HOST_GATE && r.gate == 0x51 &&
            r.rip == start(p, GATE) && r.instructions == 0,
            "rejected executable fragment leaves real gate executable");
    api(p, anyps5_qemu_cpu_protect_range(p->cpu, code_base, PAGE, 0), "revoke complete gate page");
    r = execute(p, GATE);
    fault(p, GATE, r, code_base, PAGE, 0);
    require((r.error_code & 16) && r.instructions == 0,
            "NONE gate page raises instruction-fetch fault before host dispatch");
    api(p, anyps5_qemu_cpu_protect_range(p->cpu, code_base, PAGE, 5), "restore complete code page");
    unchanged(p);
}

static void masked(Proof *p)
{
    uint8_t mask[32] = {0}, observed[32], expected[32];
    put32(mask, 0x80000000);
    seed(p);
    fragment(p, 516, 28, 0);
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 1, mask), "set one selected mask lane");
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    completed(p, MASK_LOAD, execute(p, MASK_LOAD));
    memset(expected, 0, 32);
    memcpy(expected, p->expected + 512, 4);
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "get masked load");
    require(!memcmp(observed, expected, 32),
            "masked-off NONE lanes cause no read and become zero");
    unchanged(p);
    unchanged_flags(p);
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 0, p->vector), "set masked store source");
    completed(p, MASK_STORE, execute(p, MASK_STORE));
    memcpy(p->expected + 512, p->vector, 4);
    unchanged(p);
    put32(mask + 4, 0x80000000);
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 1, mask), "select denied mask lane");
    fault(p, MASK_STORE, execute(p, MASK_STORE), data_base + 516, 28, 1);
    require(!memcmp(p->data, p->expected, 512) &&
            !memcmp(p->data + 516, p->expected + 516, p->allocation - 516),
            "selected masked-store fault never changes denied bytes or outside guards");
    unchanged_flags(p);
    fragment(p, 516, 28, 3);
    completed(p, MASK_STORE, execute(p, MASK_STORE));
    memcpy(p->expected + 512, p->vector, 8);
    unchanged(p);
    seed(p);
    fragment(p, 516, 28, 0);
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 1, mask), "select denied masked-read lane");
    fault(p, MASK_LOAD, execute(p, MASK_LOAD), data_base + 516, 28, 0);
    unchanged(p);
    fragment(p, 516, 28, 3);
    completed(p, MASK_LOAD, execute(p, MASK_LOAD));
    memset(expected, 0, 32);
    memcpy(expected, p->expected + 512, 8);
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "get restarted masked load");
    require(!memcmp(observed, expected, 32),
            "restarted masked load produces exact selected values and zero inactive lanes");
    unchanged_flags(p);
}

static void gather_and_rep(Proof *p)
{
    uint8_t mask[32] = {0}, indices[32] = {0}, values[32], progress[32];
    put32(mask, 0x80000000);
    put32(mask + 4, 0x80000000);
    put32(indices + 4, 16);
    seed(p);
    fragment(p, 576, 4, 0);
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 1, mask), "seed gather mask");
    api(p, anyps5_qemu_cpu_set_ymm(p->cpu, 2, indices), "seed gather indices");
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    fault(p, GATHER, execute(p, GATHER), data_base + 576, 4, 0);
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, values), "read partial gather destination");
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 1, progress), "read gather restart mask");
    uint32_t lane0mask = little(progress, 4);
    require(lane0mask == 0 && !memcmp(values, p->expected + 512, 4),
            "gather completed allowed lane and restart mask agree");
    require(little(progress + 4, 4) == 0x80000000 &&
            !memcmp(values + 4, p->vector + 4, 28) &&
            !memcmp(progress + 8, mask + 8, 24),
            "gather denied lane remains pending and inactive lanes stay untouched");
    unchanged(p);
    unchanged_flags(p);
    fragment(p, 576, 4, 3);
    completed(p, GATHER, execute(p, GATHER));
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, values), "read restarted gather");
    api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 1, progress), "read completed gather mask");
    require(!memcmp(values, p->expected + 512, 4) &&
            !memcmp(values + 4, p->expected + 576, 4) &&
            !memcmp(values + 8, p->vector + 8, 24) && !little(progress, 8),
            "gather restart completes pending selected lanes only");
    unchanged(p);
    seed(p);
    fragment(p, 514, 2, 0);
    set(p, ANYPS5_QEMU_RSI, data_base + 1024);
    set(p, ANYPS5_QEMU_RDI, data_base + 512);
    set(p, ANYPS5_QEMU_RCX, 4);
    fault(p, REP_COPY, execute(p, REP_COPY), data_base + 514, 2, 1);
    memcpy(p->expected + 512, p->expected + 1024, 2);
    require(get(p, ANYPS5_QEMU_RCX) == 2 &&
            get(p, ANYPS5_QEMU_RDI) == data_base + 514 &&
            get(p, ANYPS5_QEMU_RSI) == data_base + 1026,
            "REP MOVSB fault preserves exact two-byte architectural progress");
    unchanged(p);
    require(get(p, ANYPS5_QEMU_RFLAGS) == (FLAGS | UINT64_C(0x10000)),
            "intermediate REP fault preserves arithmetic/control flags and exact RF restart state");
    fragment(p, 514, 2, 3);
    completed(p, REP_COPY, execute(p, REP_COPY));
    memcpy(p->expected + 514, p->expected + 1026, 2);
    require(get(p, ANYPS5_QEMU_RCX) == 0 &&
            get(p, ANYPS5_QEMU_RDI) == data_base + 516 &&
            get(p, ANYPS5_QEMU_RSI) == data_base + 1028,
            "REP restart resumes at pending byte without replaying completed bytes");
    unchanged(p);
    unchanged_flags(p);
}

static void masked_load_families(Proof *p)
{
    static const struct {
        enum Fixture load, alias;
        size_t width, lane;
    } families[] = {
        {MASK_LOAD_PS128, MASK_ALIAS_PS128, 16, 4},
        {MASK_LOAD, MASK_ALIAS_PS256, 32, 4},
        {MASK_LOAD_PD128, MASK_ALIAS_PD128, 16, 8},
        {MASK_LOAD_PD256, MASK_ALIAS_PD256, 32, 8},
        {MASK_LOAD_D128, MASK_ALIAS_D128, 16, 4},
        {MASK_LOAD_D256, MASK_ALIAS_D256, 32, 4},
        {MASK_LOAD_Q128, MASK_ALIAS_Q128, 16, 8},
        {MASK_LOAD_Q256, MASK_ALIAS_Q256, 32, 8}
    };
    for (size_t family = 0; family < sizeof(families) / sizeof(families[0]); ++family) {
        size_t width = families[family].width, lane = families[family].lane;
        for (unsigned alias = 0; alias < 2; ++alias) {
            enum Fixture instruction = alias ? families[family].alias : families[family].load;
            uint8_t mask[32] = {0}, expected[32] = {0}, observed[32];
            seed(p);
            fragment(p, 512, width, 0);
            api(p, anyps5_qemu_cpu_set_ymm(p->cpu, alias ? 0 : 1, mask),
                "set zero mask over entirely NONE masked operand");
            set(p, ANYPS5_QEMU_RDI, data_base + 512);
            completed(p, instruction, execute(p, instruction));
            api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read zero-mask destination");
            require(!memcmp(observed, expected, 32),
                    "zero-mask PS/PD/D/Q XMM/YMM loads access no NONE bytes and zero destination");
            unchanged(p);
            unchanged_flags(p);
            seed(p);
            mask[lane - 1] = 0x80;
            mask[width - 1] = 0x80;
            if (width > 2 * lane) {
                fragment(p, 512 + lane, width - 2 * lane, 0);
            }
            api(p, anyps5_qemu_cpu_set_ymm(p->cpu, alias ? 0 : 1, mask),
                "select first and last masked lanes around NONE middle");
            set(p, ANYPS5_QEMU_RDI, data_base + 512);
            completed(p, instruction, execute(p, instruction));
            memcpy(expected, p->expected + 512, lane);
            memcpy(expected + width - lane, p->expected + 512 + width - lane, lane);
            api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read sparse selected masked lanes");
            require(!memcmp(observed, expected, 32),
                    "masked lane width/sign/alias semantics yield independently selected bytes and VEX upper-zero");
            unchanged(p);
            unchanged_flags(p);
            seed(p);
            memset(mask, 0, sizeof(mask));
            mask[lane - 1] = 0x80;
            mask[2 * lane - 1] = 0x80;
            fragment(p, 512 + lane, lane, 0);
            api(p, anyps5_qemu_cpu_set_ymm(p->cpu, alias ? 0 : 1, mask),
                "select permitted first and denied second masked lane");
            set(p, ANYPS5_QEMU_RDI, data_base + 512);
            AnyPS5QemuRunResult r = execute(p, instruction);
            fault(p, instruction, r, data_base + 512 + lane, lane, 0);
            require(r.instructions == 0, "selected masked-load fault retires no instruction");
            api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read masked-load destination after fault");
            require(!memcmp(observed, alias ? mask : p->vector, 32),
                    "selected masked-load PF preserves full destination including aliased mask and upper half");
            if (!alias) {
                api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 1, observed), "read distinct faulting mask");
                require(!memcmp(observed, mask, 32), "masked-load PF preserves distinct source mask");
            }
            unchanged(p);
            unchanged_flags(p);
            fragment(p, 512 + lane, lane, 3);
            completed(p, instruction, execute(p, instruction));
            memset(expected, 0, sizeof(expected));
            memcpy(expected, p->expected + 512, 2 * lane);
            api(p, anyps5_qemu_cpu_get_ymm(p->cpu, 0, observed), "read restarted masked family load");
            require(!memcmp(observed, expected, 32),
                    "masked family retry reads exactly original selected lanes after restoring permission");
            unchanged(p);
            unchanged_flags(p);
        }
    }
}

int main(int argc, char **argv)
{
    Proof p = {0};
    char error[256] = {0};
    uint64_t code_id, data_id;
    require(argc == 2 || (argc == 3 &&
            (!strcmp(argv[2], "--tlb") || !strcmp(argv[2], "--ymm") ||
             !strcmp(argv[2], "--masked"))),
            "usage: data-fragment-proof fixture.bin [--tlb|--ymm|--masked]");
    long host_page = sysconf(_SC_PAGESIZE);
    require(host_page >= PAGE && host_page <= 65536, "supported native host page size");
    p.allocation = host_page > 4 * PAGE ? host_page : 4 * PAGE;
    require(!posix_memalign((void **)&p.code, host_page, p.allocation) &&
            !posix_memalign((void **)&p.data, host_page, p.allocation),
            "allocate stable host-aligned shared backings");
    p.expected = malloc(p.allocation);
    require(p.expected != NULL, "allocate independent full-backing oracle");
    memset(p.code, 0, p.allocation);
    FILE *fixture = fopen(argv[1], "rb");
    require(fixture != NULL, "open assembled actual x86 fixture");
    size_t length = fread(p.code, 1, PAGE, fixture);
    require(!ferror(fixture) && feof(fixture) && fclose(fixture) == 0 &&
            length > 16 + FIXTURE_COUNT * 8 && !memcmp(p.code, "APS5FRG1", 8) &&
            little(p.code + 8, 4) == FIXTURE_COUNT && !little(p.code + 12, 4),
            "fixture schema, table and entire executable extent are valid");
    for (unsigned i = 0; i < FIXTURE_COUNT; ++i) {
        p.offsets[i] = little(p.code + 16 + i * 8, 4);
        p.lengths[i] = little(p.code + 20 + i * 8, 4);
        require(p.offsets[i] >= 16 + FIXTURE_COUNT * 8 && p.lengths[i] > 0 &&
                p.offsets[i] < length && p.lengths[i] <= length - p.offsets[i],
                "every actual assembly instruction has a bounded extent");
    }
    require(p.lengths[PREFIX_LOAD] == 5 && p.lengths[PREFIX_STORE] == 5,
            "two-instruction cache-bypass fixture has independently known fault PC");
    for (unsigned i = 0; i < 32; ++i) {
        p.vector[i] = 0xe3 - 5 * i;
    }
    p.cpu = anyps5_qemu_cpu_create(error, sizeof(error));
    if (!p.cpu) {
        fprintf(stderr, "FAIL: create native embedded CPU: %s\n", error);
        return 1;
    }
    api(&p, anyps5_qemu_cpu_register_backing(p.cpu, p.code, p.allocation, &code_id), "register code backing");
    api(&p, anyps5_qemu_cpu_register_backing(p.cpu, p.data, p.allocation, &data_id), "register shared data backing");
    api(&p, anyps5_qemu_cpu_map_alias(p.cpu, code_base, code_id, 0, PAGE, 5), "map actual x86 code RX");
    api(&p, anyps5_qemu_cpu_map_alias(p.cpu, data_base, data_id, 0, 4 * PAGE, 3), "map shared data RW");
    api(&p, anyps5_qemu_cpu_map_alias(p.cpu, alias_base, data_id, 0, PAGE, 3), "map independent-policy physical alias");
    if (argc == 2 || !strcmp(argv[2], "--tlb")) {
        cache_prefix(&p);
    }
    if (argc == 2 || !strcmp(argv[2], "--ymm")) {
        ymm_preflight(&p);
    }
    if (argc == 2) {
        data_permissions(&p);
        widths(&p);
        locked(&p);
        x87(&p);
        aliases_and_rejections(&p);
        masked(&p);
        masked_load_families(&p);
        gather_and_rep(&p);
    }
    if (argc == 3 && !strcmp(argv[2], "--masked")) {
        masked(&p);
        masked_load_families(&p);
    }
    api(&p, anyps5_qemu_cpu_destroy(p.cpu), "destroy CPU before backing release");
    free(p.expected);
    free(p.data);
    free(p.code);
    puts("PASS: actual x86 data-fragment permissions, preflight and architectural restart");
    return 0;
}
