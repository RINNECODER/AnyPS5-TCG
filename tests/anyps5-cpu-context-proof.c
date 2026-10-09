#include "qemu/anyps5-cpu.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void check_api(AnyPS5QemuCpu *cpu, int result, const char *operation)
{
    if (result) {
        fprintf(stderr, "FAIL: %s: %s\n", operation,
                anyps5_qemu_cpu_error(cpu));
        exit(1);
    }
}

static uint64_t word(const uint8_t *bytes)
{
    uint64_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static uint32_t dword(const uint8_t *bytes)
{
    uint32_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static uint16_t half(const uint8_t *bytes)
{
    uint16_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static void set_reg(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg,
                    uint64_t value)
{
    check_api(cpu, anyps5_qemu_cpu_set(cpu, reg, value), "set guest register");
}

typedef struct ForeignOwnerAccess {
    AnyPS5QemuCpu *cpu;
    AnyPS5QemuContext *context;
    AnyPS5QemuContext *created;
    int results[4];
} ForeignOwnerAccess;

static void *access_from_nonowner(void *opaque)
{
    ForeignOwnerAccess *access = opaque;

    access->results[0] = anyps5_qemu_cpu_context_create(access->cpu,
                                                      &access->created);
    access->results[1] = anyps5_qemu_cpu_context_save(access->cpu,
                                                    access->context);
    access->results[2] = anyps5_qemu_cpu_context_restore(access->cpu,
                                                       access->context);
    access->results[3] = anyps5_qemu_cpu_context_destroy(access->cpu,
                                                       access->context);
    return NULL;
}

static void reject_context(AnyPS5QemuCpu *cpu, AnyPS5QemuContext *context,
                            const char *description)
{
    if (!anyps5_qemu_cpu_context_save(cpu, context) ||
        !anyps5_qemu_cpu_context_restore(cpu, context) ||
        !anyps5_qemu_cpu_context_destroy(cpu, context)) {
        fprintf(stderr, "FAIL: context preflight accepted %s\n", description);
        exit(1);
    }
}

static void preflight(AnyPS5QemuCpu *cpu, AnyPS5QemuContext *live, size_t page)
{
    pthread_t other;
    max_align_t foreign_storage;
    AnyPS5QemuContext *retired = NULL, *replacement = NULL;
    AnyPS5QemuContext *rejected_output = live;
    ForeignOwnerAccess access = {.cpu = cpu, .context = live, .created = live};

    require(anyps5_qemu_cpu_context_create(cpu, NULL) != 0,
            "context creation rejects a null output without state mutation");
    reject_context(cpu, NULL, "null handle");
    reject_context(cpu, (AnyPS5QemuContext *)&foreign_storage,
                   "foreign unowned storage");
    /* Readable foreign storage cannot expose a pre-membership dereference. */
    void *inaccessible = mmap(NULL, page, PROT_NONE,
                             MAP_PRIVATE | MAP_ANON, -1, 0);
    require(inaccessible != MAP_FAILED,
            "allocate inaccessible foreign context");
    reject_context(cpu, inaccessible, "inaccessible unregistered storage");
    require(munmap(inaccessible, page) == 0,
            "release inaccessible foreign context");
    require(anyps5_qemu_cpu_context_create(NULL, &rejected_output) != 0 &&
            rejected_output == live,
            "null CPU creation preflight leaves output unchanged");
    reject_context(NULL, live, "null CPU");
    require(anyps5_qemu_cpu_context_create(
                (AnyPS5QemuCpu *)&foreign_storage, &rejected_output) != 0 &&
            rejected_output == live,
            "foreign CPU creation preflight leaves output unchanged");
    reject_context((AnyPS5QemuCpu *)&foreign_storage, live, "foreign CPU");
    check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &retired),
              "capture temporary context for retirement");
    check_api(cpu, anyps5_qemu_cpu_context_destroy(cpu, retired),
              "retire temporary context");
    check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &replacement),
              "create live replacement after handle retirement");
    reject_context(cpu, retired, "destroyed handle after another allocation");
    check_api(cpu, anyps5_qemu_cpu_context_destroy(cpu, replacement),
              "retire valid replacement context");
    require(pthread_create(&other, NULL, access_from_nonowner, &access) == 0 &&
            pthread_join(other, NULL) == 0,
            "join foreign caller before owner resumes execution");
    for (unsigned operation = 0; operation < 4; operation++) {
        require(access.results[operation] != 0,
                "context operation rejects a non-owner caller");
    }
    require(access.created == live,
            "non-owner context creation leaves caller output unchanged");
}

/* Exercise membership through the public API, independently of its index. */
static void mixed_lifetimes(AnyPS5QemuCpu *cpu)
{
    AnyPS5QemuContext *contexts[4], *retired[256], *fresh;
    const unsigned order[] = {1, 3, 0, 2};
    uint64_t expected[] = {11, 22, 33, 44};
    bool alive[] = {true, true, true, true};

    for (unsigned i = 0; i < 4; i++) {
        set_reg(cpu, ANYPS5_QEMU_RAX, expected[i]);
        check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &contexts[i]),
                  "capture independently valued lifetime context");
    }
    for (unsigned step = 0; step < 4; step++) {
        const unsigned removed = order[step];
        check_api(cpu, anyps5_qemu_cpu_context_destroy(cpu, contexts[removed]),
                  "retire context in mixed creation order");
        alive[removed] = false;
        for (unsigned i = 0; i < 4; i++) {
            if (!alive[i]) {
                reject_context(cpu, contexts[i], "mixed-order retired context");
                continue;
            }
            uint64_t observed = 0;
            check_api(cpu, anyps5_qemu_cpu_context_restore(cpu, contexts[i]),
                      "restore survivor of unrelated retirement");
            check_api(cpu, anyps5_qemu_cpu_get(cpu, ANYPS5_QEMU_RAX, &observed),
                      "read surviving snapshot value");
            require(observed == expected[i],
                    "retiring another context changed a surviving snapshot");
            expected[i] += 100;
            set_reg(cpu, ANYPS5_QEMU_RAX, expected[i]);
            check_api(cpu, anyps5_qemu_cpu_context_save(cpu, contexts[i]),
                      "save survivor after unrelated retirement");
        }
    }
    for (unsigned i = 0; i < 256; i++) {
        check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &retired[i]),
                  "create after all previous contexts retired");
        for (unsigned j = 0; j < 4; j++) {
            require(retired[i] != contexts[j],
                    "mixed-order retired address reused");
        }
        for (unsigned j = 0; j < i; j++) {
            require(retired[i] != retired[j],
                    "retired address reused during churn");
        }
        check_api(cpu, anyps5_qemu_cpu_context_destroy(cpu, retired[i]),
                  "retire churn context");
    }
    set_reg(cpu, ANYPS5_QEMU_RAX, 0x12345678);
    check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &fresh),
              "capture fresh context after retirement churn");
    for (unsigned i = 0; i < 256; i++) {
        require(fresh != retired[i], "fresh context reused a retired address");
        reject_context(cpu, retired[i],
                       "retired handle after allocation churn");
    }
    set_reg(cpu, ANYPS5_QEMU_RAX, 0);
    check_api(cpu, anyps5_qemu_cpu_context_restore(cpu, fresh),
              "restore fresh snapshot after rejected retired calls");
    uint64_t observed = 0;
    check_api(cpu, anyps5_qemu_cpu_get(cpu, ANYPS5_QEMU_RAX, &observed),
              "read fresh snapshot after rejected retired calls");
    require(observed == 0x12345678, "retired calls damaged the fresh snapshot");
    /* CPU destruction must own both this live state and all retired handles. */
}

static void reach(AnyPS5QemuCpu *cpu, uint64_t until)
{
    AnyPS5QemuRunResult result;
    check_api(cpu, anyps5_qemu_cpu_run_until(cpu, 512, until, &result),
              "run actual context guest");
    require(result.reason == ANYPS5_QEMU_STOP_ADDRESS && result.rip == until,
            "restored guest reaches independently selected control endpoint");
}

static void prepare(AnyPS5QemuCpu *cpu, uint8_t *data, unsigned index,
                    uint64_t registers[16])
{
    const uint64_t base = UINT64_C(0x200000);
    const size_t input = 0x1000 + index * 0x400;
    const size_t output = 0x2000 + index * 0x800;
    const double operands[2][2] = {{1.25, 2.5}, {7.5, 0.25}};
    const double divisors[2] = {3, 0};
    const uint16_t controls[2] = {0x077f, 0x0b7f};
    const uint32_t mxcsrs[2] = {0x3f81, 0xdfc4};
    const float vectors[2][8] = {
        {1.25f, 2, 3, 4, 5, 6, 7, 8},
        {3.25f, 9, 10, 11, 12, 13, 14, 15}
    };
    const uint64_t tls_values[2][2] = {
        {UINT64_C(0x1122334455667788), UINT64_C(0x123456789abcdef0)},
        {UINT64_C(0xaabbccddeeff0011), UINT64_C(0xfedcba9876543210)}
    };

    memcpy(data + input, operands[index], sizeof(operands[index]));
    memcpy(data + input + 24, &divisors[index], sizeof(divisors[index]));
    memcpy(data + input + 64, &controls[index], sizeof(controls[index]));
    memcpy(data + input + 72, &mxcsrs[index], sizeof(mxcsrs[index]));
    memcpy(data + input + 96, vectors[index], sizeof(vectors[index]));
    for (unsigned reg = 1; reg < 16; reg++) {
        float lanes[8];
        for (unsigned lane = 0; lane < 8; lane++) {
            lanes[lane] = (float)(index * 1000 + reg * 16 + lane + 1);
        }
        memcpy(data + input + 96 + reg * 32, lanes, sizeof(lanes));
    }
    memcpy(data + 0x500 + index * 0x200, &tls_values[index][0], 8);
    memcpy(data + 0x600 + index * 0x200, &tls_values[index][1], 8);
    memset(data + output, 0xcc, 1024);
    for (unsigned reg = 0; reg < 16; reg++) {
        registers[reg] = UINT64_C(0x123400000000) + index * 0x1000 + reg * 17;
    }
    registers[ANYPS5_QEMU_RSP] = base + 0x3f00 - index * 0x100;
    registers[ANYPS5_QEMU_RSI] = base + output;
    registers[ANYPS5_QEMU_RDI] = base + input;
    for (unsigned reg = 0; reg < 16; reg++) {
        set_reg(cpu, (enum AnyPS5QemuRegister)reg, registers[reg]);
    }
    set_reg(cpu, ANYPS5_QEMU_FS_BASE, base + 0x500 + index * 0x200);
    set_reg(cpu, ANYPS5_QEMU_GS_BASE, base + 0x600 + index * 0x200);
    set_reg(cpu, ANYPS5_QEMU_RIP, UINT64_C(0x100000));
    reach(cpu, UINT64_C(0x100200));
    for (unsigned reg = 0; reg < 16; reg++) {
        set_reg(cpu, (enum AnyPS5QemuRegister)reg, registers[reg]);
    }
    set_reg(cpu, ANYPS5_QEMU_RIP, UINT64_C(0x100300) + index * 0x500);
    set_reg(cpu, ANYPS5_QEMU_RFLAGS, index ? 2 : 0x403);
}

static void observe(const uint8_t *data, unsigned index,
                     const uint64_t registers[16])
{
    const uint8_t *output = data + 0x2000 + index * 0x800;
    const float expected_vectors[2][8] = {
        {2.5f, 4, 6, 8, 10, 12, 14, 16},
        {6.5f, 18, 20, 22, 24, 26, 28, 30}
    };
    const uint64_t fs_values[2] = {UINT64_C(0x1122334455667788),
                                   UINT64_C(0xaabbccddeeff0011)};
    const uint64_t gs_values[2] = {UINT64_C(0x123456789abcdef0),
                                   UINT64_C(0xfedcba9876543210)};

    for (unsigned reg = 0; reg < 16; reg++) {
        require(word(output + reg * 8) == registers[reg],
                "restored GPR/stack/input/output state executes guest stores");
    }
    require(word(output + 128) == (index ? 2u : 0x403u) &&
            dword(output + 224) == (index ? 0xb2u : 0xa1u),
            "idle RFLAGS capture preserves carry branch and direction state");
    require(word(output + 136) == fs_values[index] &&
            word(output + 144) == gs_values[index],
            "restored FS/GS resolve the correct per-context memory");
    require(!memcmp(output + 256, expected_vectors[index], 32),
            "restored full YMM state produces independent eight-lane arithmetic");
    for (unsigned reg = 1; reg < 16; reg++) {
        for (unsigned lane = 0; lane < 8; lane++) {
            float observed;
            memcpy(&observed, output + 256 + reg * 32 + lane * 4, 4);
            const float expected = (float)(index * 2000 + reg * 32 +
                                           lane * 2 + 2);
            require(observed == expected,
                    "all sixteen YMM registers retain independent lane patterns");
        }
    }
    require(half(output + 800) == (index ? 0x0b7fu : 0x077fu) &&
            (half(output + 804) & 0x383f) == (index ? 0x3004u : 0x3020u) &&
            half(output + 808) == 0x0fff,
            "restored x87 environment exposes correct nonzero TOP and tags");
    require(word(output + 152) == (index ? 8u : 3u) &&
            half(output + 208) == (index ? 0x0b7fu : 0x077fu) &&
            (half(output + 210) & 0x383f) == (index ? 0x24u : 0x20u),
            "restored x87 values/TOP/tags/control perform independent rounding");
    require(word(output + 200) == (index ? 7u : 2u) &&
            dword(output + 192) == (index ? 0xdfe4u : 0x3fa1u) &&
            dword(output + 196) == (index ? 0xdfe4u : 0x3fa1u),
            "restored MXCSR retains rounding/DAZ/FTZ and accrued exceptions");
    require(output[228] == 0xcc && output[255] == 0xcc &&
            output[768] == 0xcc && output[799] == 0xcc &&
            output[828] == 0xcc && output[1023] == 0xcc,
            "guest continuation preserves trailing output guards");
}

int main(int argc, char **argv)
{
    char error[256] = {0};
    const long host_page = sysconf(_SC_PAGESIZE);
    const size_t size = host_page > 16384 ? (size_t)host_page : 16384;
    uint8_t *code = NULL, *data = NULL;
    uint64_t registers[2][16];
    AnyPS5QemuContext *contexts[2] = {NULL, NULL};
    AnyPS5QemuCpu *cpu;
    FILE *fixture;

    require(argc == 2 && host_page > 0,
            "supply assembled x86 context guest binary");
    require(posix_memalign((void **)&code, (size_t)host_page, size) == 0 &&
            posix_memalign((void **)&data, (size_t)host_page, size) == 0,
            "allocate complete aligned physical backing");
    memset(code, 0, size);
    memset(data, 0, size);
    fixture = fopen(argv[1], "rb");
    require(fixture != NULL && fread(code, 1, size, fixture) == 0xf11 &&
            fgetc(fixture) == EOF && !ferror(fixture),
            "load actual assembled x86 fixture with all selected endpoints");
    require(fclose(fixture) == 0, "close guest fixture");
    cpu = anyps5_qemu_cpu_create(error, sizeof(error));
    if (!cpu) {
        fprintf(stderr, "FAIL: create CPU: %s\n", error);
        return 1;
    }
    check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, UINT64_C(0x100000),
              code, size, ANYPS5_QEMU_READ | ANYPS5_QEMU_EXECUTE), "map guest");
    check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, UINT64_C(0x200000),
              data, size, ANYPS5_QEMU_READ | ANYPS5_QEMU_WRITE), "map data");
    prepare(cpu, data, 0, registers[0]);
    check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &contexts[0]),
              "capture prepared first guest context");
    check_api(cpu, anyps5_qemu_cpu_context_create(cpu, &contexts[1]),
              "allocate second context with first guest state");
    prepare(cpu, data, 1, registers[1]);
    check_api(cpu, anyps5_qemu_cpu_context_save(cpu, contexts[1]),
              "replace second context with independently prepared state");
    preflight(cpu, contexts[1], (size_t)host_page);
    reach(cpu, UINT64_C(0x100f10));
    observe(data, 1, registers[1]);
    for (unsigned pass = 0; pass < 4; pass++) {
        const unsigned index = pass % 2;
        check_api(cpu, anyps5_qemu_cpu_context_restore(cpu, contexts[index]),
                  "restore saved guest context");
        reach(cpu, UINT64_C(0x100f00) + index * 0x10);
        observe(data, index, registers[index]);
    }
    anyps5_qemu_cpu_stop(cpu);
    check_api(cpu, anyps5_qemu_cpu_context_restore(cpu, contexts[0]),
              "restore context while session cancellation is pending");
    AnyPS5QemuRunResult stopped;
    check_api(cpu, anyps5_qemu_cpu_run(cpu, 512, &stopped),
              "observe session stop after context restore");
    require(stopped.reason == ANYPS5_QEMU_REQUESTED_STOP &&
            stopped.instructions == 0 && stopped.rip == UINT64_C(0x100300),
            "context restore must preserve session-level cancellation");
    check_api(cpu, anyps5_qemu_cpu_clear_stop(cpu),
              "clear terminal keeper stop before owner retirement");
    for (unsigned index = 0; index < 2; index++) {
        check_api(cpu, anyps5_qemu_cpu_context_destroy(cpu, contexts[index]),
                  "retire context on idle owner");
    }
    mixed_lifetimes(cpu);
    check_api(cpu, anyps5_qemu_cpu_destroy(cpu), "destroy owner CPU");
    free(data);
    free(code);
    puts("PASS: two restored x86 contexts retain GPR/flags/control/TLS, "
         "x87 and full YMM/MXCSR results across four switches");
    return 0;
}
