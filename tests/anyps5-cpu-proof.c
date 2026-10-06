#include "qemu/anyps5-cpu.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void check_api(AnyPS5QemuCpu *cpu, int result, const char *operation)
{
    if (result != 0) {
        fprintf(stderr, "FAIL: %s: %s\n", operation, anyps5_qemu_cpu_error(cpu));
        exit(1);
    }
}

static void set_reg(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg, uint64_t value)
{
    check_api(cpu, anyps5_qemu_cpu_set(cpu, reg, value), "set register");
}

static uint64_t get_reg(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg)
{
    uint64_t value = 0;
    check_api(cpu, anyps5_qemu_cpu_get(cpu, reg, &value), "get register");
    return value;
}

static AnyPS5QemuRunResult run(AnyPS5QemuCpu *cpu, uint64_t budget)
{
    AnyPS5QemuRunResult result;
    check_api(cpu, anyps5_qemu_cpu_run(cpu, budget, &result), "run");
    fprintf(stderr, "stop=%u instructions=%llu rip=0x%llx vector=%u address=0x%llx\n",
            result.reason, (unsigned long long)result.instructions,
            (unsigned long long)result.rip, result.vector,
            (unsigned long long)result.address);
    return result;
}

int main(void)
{
    char error[256] = {0};
    AnyPS5QemuCpu *cpu = anyps5_qemu_cpu_create(error, sizeof(error));
    AnyPS5QemuRunResult result;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t region_size = page < 16384 ? 16384 : page;
    uint8_t *code = NULL;
    uint8_t *data = NULL;
    float vectors[8];
    uint64_t saved_return = 0;
    const float left[8] = {1,2,3,4,5,6,7,8};
    const float right[8] = {2,4,6,8,10,12,14,16};
    const float expected[8] = {3,6,9,12,15,18,21,24};
    const float expected_xmm[8] = {3,6,9,12,0,0,0,0};
    const float old_destination[8] = {99,99,99,99,99,99,99,99};
    const uint8_t avx256[] = {
        0xc5,0xfc,0x10,0x07,
        0xc5,0xfc,0x10,0x0e,
        0xc5,0xfc,0x58,0xd1,
        0xc5,0xfc,0x11,0x12
    };
    const uint8_t avx128[] = {0xc5,0xf8,0x58,0xd1};
    const uint8_t host_call[] = {
        0x48,0xb8,0x00,0x03,0x10,0x00,0x00,0x00,0x00,0x00,
        0xff,0xd0,0x48,0x89,0xc3
    };
    const uint8_t syscall[] = {0xb8,0x01,0x00,0x00,0x00,0x0f,0x05};
    const uint8_t loop[] = {0xeb,0xfe};
    const uint8_t store[] = {0x48,0x89,0x07};
    const uint8_t unsupported[] = {0x0f,0x0b};
    const uint8_t cpuid[] = {0x0f,0xa2};
    const uint8_t xgetbv[] = {0x0f,0x01,0xd0};
    const uint8_t xsave[] = {0x48,0x0f,0xae,0x27};
    const uint8_t xrstor[] = {0x48,0x0f,0xae,0x2f};
    const uint8_t avx2[] = {0xc5,0xfd,0xfe,0xd1};
    const uint8_t f16c[] = {
        0xc4,0xe2,0x7d,0x13,0xd0, 0xc4,0xe3,0x7d,0x1d,0xd3,0x00
    };
    const uint8_t fma[] = {0xc4,0xe2,0x7d,0x98,0xd1};
    const uint32_t integers_left[8] = {
        1,0xffffffff,0x7fffffff,0x80000000,0x12345678,17,0,0xfffffffe
    };
    const uint32_t integers_right[8] = {
        2,1,1,0xffffffff,0x11111111,25,0xffffffff,3
    };
    const uint32_t integers_expected[8] = {
        3,0,0x80000000,0x7fffffff,0x23456789,42,0xffffffff,1
    };
    const uint16_t half_expected[16] = {
        0x3c00,0xc000,0x3800,0,0x8000,0x7bff,0x0400,0x0001,
        0,0,0,0,0,0,0,0
    };
    const float converted_expected[8] = {
        1,-2,0.5f,0.0f,-0.0f,65504,0x1p-14f,0x1p-24f
    };
    const float fma_destination[8] = {0x1.000002p0f,2,2,2,2,2,2,2};
    const float fma_addend[8] = {-0x1.000004p0f,2,3,4,5,6,7,8};
    const float fma_multiplier[8] = {0x1.000002p0f,4,6,8,10,12,14,16};
    const float fma_expected[8] = {0x1p-46f,10,15,20,25,30,35,40};
    const float zero_vector[8] = {0};
    uint64_t saved_components;

    if (!cpu) {
        fprintf(stderr, "FAIL: create CPU: %s\n", error);
        return 1;
    }
    require(posix_memalign((void **)&code, page, region_size) == 0, "code allocation");
    require(posix_memalign((void **)&data, page, region_size) == 0, "data allocation");
    memset(code, 0xcc, region_size);
    memset(data, 0xa5, region_size);
    memcpy(code, avx256, sizeof(avx256));
    memcpy(code+0x100, avx128, sizeof(avx128));
    memcpy(code+0x200, host_call, sizeof(host_call));
    code[0x300] = 0xc3;
    memcpy(code+0x400, syscall, sizeof(syscall));
    memcpy(code+0x500, loop, sizeof(loop));
    memcpy(code+0x600, store, sizeof(store));
    memcpy(code+0x610, unsupported, sizeof(unsupported));
    memcpy(code+0x700, cpuid, sizeof(cpuid));
    memcpy(code+0x710, xgetbv, sizeof(xgetbv));
    memcpy(code+0x730, xsave, sizeof(xsave));
    memcpy(code+0x740, xrstor, sizeof(xrstor));
    memcpy(code+0x750, avx2, sizeof(avx2));
    memcpy(code+0x760, f16c, sizeof(f16c));
    memcpy(code+0x780, fma, sizeof(fma));
    memcpy(data, left, sizeof(left));
    memcpy(data+32, right, sizeof(right));
    check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, 0x100000, code, region_size,
              ANYPS5_QEMU_READ | ANYPS5_QEMU_EXECUTE), "map code");
    check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, 0x200000, data, region_size,
              ANYPS5_QEMU_READ | ANYPS5_QEMU_WRITE), "map data");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100010, 42), "add vector gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100104, 43), "add xmm gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100300, 44), "add native gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x10020f, 45), "add return gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100702, 50), "add CPUID gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100713, 51), "add XGETBV gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100734, 52), "add XSAVE gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100744, 53), "add XRSTOR gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100754, 54), "add AVX2 gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x10076b, 55), "add F16C gate");
    check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100785, 56), "add FMA gate");
    set_reg(cpu, ANYPS5_QEMU_RDI, 0x200000);
    set_reg(cpu, ANYPS5_QEMU_RSI, 0x200020);
    set_reg(cpu, ANYPS5_QEMU_RDX, 0x200040);
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100000);
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 2, old_destination), "seed YMM2");
    result = run(cpu, 32);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 42 &&
            result.instructions == 4 && result.rip == 0x100010, "four AVX instructions reach gate");
    require(memcmp(data+64, expected, 32) == 0, "YMM memory result is 3,6,9,12,15,18,21,24");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 2, vectors), "read YMM2");
    require(memcmp(vectors, expected, 32) == 0, "three-operand destination ignores old YMM2");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 0, vectors), "read source YMM0");
    require(memcmp(vectors, left, 32) == 0, "YMM0 source unchanged");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 1, vectors), "read source YMM1");
    require(memcmp(vectors, right, 32) == 0, "YMM1 source unchanged");
    require(data[96] == 0xa5 && data[127] == 0xa5, "vector memory guard unchanged");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 2, old_destination), "seed upper lanes");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100100);
    result = run(cpu, 32);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 43 &&
            result.instructions == 1 && result.rip == 0x100104, "VEX128 reaches gate");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 2, vectors), "read VEX128 destination");
    require(memcmp(vectors, expected_xmm, 32) == 0, "VEX128 clears upper YMM lanes");

    const uint32_t cpuid_queries[][2] = {{0,0},{1,0},{7,0},{13,0},{13,2},{4,0}};
    uint64_t cpuid_results[6][4];
    for (unsigned query = 0; query < 6; query++) {
        set_reg(cpu, ANYPS5_QEMU_RAX, cpuid_queries[query][0]);
        set_reg(cpu, ANYPS5_QEMU_RCX, cpuid_queries[query][1]);
        set_reg(cpu, ANYPS5_QEMU_RIP, 0x100700);
        result = run(cpu, 8);
        require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 50 &&
                result.instructions == 1, "actual CPUID returns to host gate");
        cpuid_results[query][0] = get_reg(cpu, ANYPS5_QEMU_RAX);
        cpuid_results[query][1] = get_reg(cpu, ANYPS5_QEMU_RBX);
        cpuid_results[query][2] = get_reg(cpu, ANYPS5_QEMU_RCX);
        cpuid_results[query][3] = get_reg(cpu, ANYPS5_QEMU_RDX);
    }
    require(cpuid_results[0][0] >= 13 && cpuid_results[0][1] == 0x756e6547 &&
            cpuid_results[0][3] == 0x49656e69 && cpuid_results[0][2] == 0x6c65746e,
            "guest CPUID reports initialized Intel model and XSAVE leaf");
    require((cpuid_results[1][2] & 0x3c001000) == 0x3c001000 &&
            (cpuid_results[2][1] & 32), "CPUID reports FMA, XSAVE, OSXSAVE, AVX, F16C and AVX2");
    require(cpuid_results[3][0] == 7 && cpuid_results[3][1] == 832 &&
            cpuid_results[3][2] == 832 && cpuid_results[3][3] == 0 &&
            cpuid_results[4][0] == 256 && cpuid_results[4][1] == 576,
            "CPUID describes architectural FP/SSE/YMM XSAVE layout");
    require((cpuid_results[5][0] & 31) == 1 &&
            ((cpuid_results[5][0] >> 5) & 7) == 1 &&
            (cpuid_results[5][1] & 4095) == 63, "CPUID cache leaf has initialized L1 data and 64-byte lines");
    set_reg(cpu, ANYPS5_QEMU_RCX, 0);
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100710);
    result = run(cpu, 8);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 51 &&
            result.instructions == 1 && get_reg(cpu, ANYPS5_QEMU_RAX) == 7 &&
            get_reg(cpu, ANYPS5_QEMU_RDX) == 0, "XGETBV enables FP/SSE/YMM state");
    memset(data+0x1000, 0, 832);
    memset(data+0x1000+832, 0xa5, 64);
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 0, left), "seed saved YMM0");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 2, expected), "seed saved YMM2");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 15, right), "seed saved YMM15");
    set_reg(cpu, ANYPS5_QEMU_RDI, 0x201000);
    set_reg(cpu, ANYPS5_QEMU_RAX, 7);
    set_reg(cpu, ANYPS5_QEMU_RDX, 0);
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100730);
    result = run(cpu, 8);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 52 &&
            result.instructions == 1, "actual XSAVE64 reaches gate");
    memcpy(&saved_components, data+0x1000+512, 8);
    require((saved_components & 6) == 6 && !(saved_components & ~7ULL),
            "XSAVE marks saved SSE and YMM components");
    require(memcmp(data+0x1000+160, left, 16) == 0 &&
            memcmp(data+0x1000+576, (const uint8_t *)left+16, 16) == 0 &&
            memcmp(data+0x1000+192, expected, 16) == 0 &&
            memcmp(data+0x1000+608, (const uint8_t *)expected+16, 16) == 0 &&
            memcmp(data+0x1000+400, right, 16) == 0 &&
            memcmp(data+0x1000+816, (const uint8_t *)right+16, 16) == 0,
            "XSAVE stores YMM0, YMM2 and YMM15 halves at independent architectural offsets");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 0, zero_vector), "clear saved YMM0");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 2, zero_vector), "clear saved YMM2");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 15, zero_vector), "clear saved YMM15");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100740);
    result = run(cpu, 8);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 53 &&
            result.instructions == 1, "actual XRSTOR64 reaches gate");
    const unsigned restored_registers[3] = {0,2,15};
    const float *restored_expected[3] = {left,expected,right};
    for (unsigned restored = 0; restored < 3; restored++) {
        check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, restored_registers[restored], vectors), "read restored YMM");
        require(memcmp(vectors, restored_expected[restored], 32) == 0,
                "XRSTOR independently restores full saved vector state");
    }
    require(data[0x1000+832] == 0xa5 && data[0x1000+895] == 0xa5,
            "XSAVE and XRSTOR preserve area guard bytes");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 0, integers_left), "seed AVX2 left");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 1, integers_right), "seed AVX2 right");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100750);
    result = run(cpu, 8);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 54 &&
            result.instructions == 1, "actual AVX2 VPADDD reaches gate");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 2, vectors), "read AVX2 result");
    require(memcmp(vectors, integers_expected, 32) == 0, "AVX2 integer lanes obey 32-bit wrapping addition");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 0, half_expected), "seed F16C source");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100760);
    result = run(cpu, 8);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 55 &&
            result.instructions == 2, "actual F16C conversion pair reaches gate");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 2, vectors), "read converted F16C singles");
    require(memcmp(vectors, converted_expected, 32) == 0, "F16C handles signs, zeros, maximum finite, minimum normal and subnormal");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 3, vectors), "read converted F16C halves");
    require(memcmp(vectors, half_expected, 32) == 0, "F16C converts known exact singles to independently expected half bits");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 0, fma_addend), "seed FMA addend");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 1, fma_multiplier), "seed FMA multiplier");
    check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 2, fma_destination), "seed FMA destination");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100780);
    result = run(cpu, 8);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 56 &&
            result.instructions == 1, "actual FMA reaches gate");
    check_api(cpu, anyps5_qemu_cpu_get_ymm(cpu, 2, vectors), "read FMA result");
    require(memcmp(vectors, fma_expected, 32) == 0, "FMA retains exact 2^-46 cancellation residual and operand ordering");

    set_reg(cpu, ANYPS5_QEMU_RSP, 0x203ff0);
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100200);
    result = run(cpu, 32);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 44 &&
            result.instructions == 2 && get_reg(cpu, ANYPS5_QEMU_RSP) == 0x203fe8,
            "guest CALL reaches native host gate");
    memcpy(&saved_return, data+0x3fe8, sizeof(saved_return));
    require(saved_return == 0x10020c, "guest CALL saved independently expected return PC");
    set_reg(cpu, ANYPS5_QEMU_RAX, 1234);
    set_reg(cpu, ANYPS5_QEMU_RSP, 0x203ff0);
    set_reg(cpu, ANYPS5_QEMU_RIP, saved_return);
    result = run(cpu, 32);
    require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 45 &&
            get_reg(cpu, ANYPS5_QEMU_RBX) == 1234, "guest receives native host result");
    set_reg(cpu, ANYPS5_QEMU_RFLAGS, 2);
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100400);
    result = run(cpu, 32);
    require(result.reason == ANYPS5_QEMU_SYSCALL && result.instructions == 2 &&
            result.rip == 0x100407 && get_reg(cpu, ANYPS5_QEMU_RAX) == 1 &&
            get_reg(cpu, ANYPS5_QEMU_RCX) == 0x100407 &&
            get_reg(cpu, ANYPS5_QEMU_R11) == 2, "SYSCALL preserves service number and RCX/R11 semantics");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100500);
    result = run(cpu, 3);
    require(result.reason == ANYPS5_QEMU_BUDGET && result.instructions == 3 &&
            result.rip == 0x100500, "backward branch obeys global instruction budget");

    check_api(cpu, anyps5_qemu_cpu_protect(cpu, 0x200000, ANYPS5_QEMU_READ), "protect data");
    set_reg(cpu, ANYPS5_QEMU_RDI, 0x200040);
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100600);
    result = run(cpu, 1);
    require(result.reason == ANYPS5_QEMU_FAULT && result.vector == 14 &&
            result.address == 0x200040 && result.instructions == 0 &&
            memcmp(data+64, expected, 32) == 0, "read-only guest write fails without modifying output");
    set_reg(cpu, ANYPS5_QEMU_RIP, 0x100610);
    result = run(cpu, 1);
    require(result.reason == ANYPS5_QEMU_UNSUPPORTED && result.vector == 6 &&
            result.rip == 0x100610, "UD2 fails explicitly at guest PC");
    anyps5_qemu_cpu_stop(cpu);
    result = run(cpu, 1);
    require(result.reason == ANYPS5_QEMU_REQUESTED_STOP && result.instructions == 0,
            "stop request prevents another guest instruction");
    check_api(cpu, anyps5_qemu_cpu_destroy(cpu), "destroy CPU");
    for (unsigned generation = 0; generation < 3; generation++) {
        memset(error, 0, sizeof(error));
        cpu = anyps5_qemu_cpu_create(error, sizeof(error));
        require(cpu != NULL, "create another CPU after destruction");
        check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, 0x100000, code,
                  region_size, ANYPS5_QEMU_READ | ANYPS5_QEMU_EXECUTE),
                  "remap code after destruction");
        check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, 0x200000, data,
                  region_size, ANYPS5_QEMU_READ | ANYPS5_QEMU_WRITE),
                  "remap data after destruction");
        check_api(cpu, anyps5_qemu_cpu_add_gate(cpu, 0x100010, 42),
                  "add gate after destruction");
        memset(data+64, 0xa5, 32);
        set_reg(cpu, ANYPS5_QEMU_RDI, 0x200000);
        set_reg(cpu, ANYPS5_QEMU_RSI, 0x200020);
        set_reg(cpu, ANYPS5_QEMU_RDX, 0x200040);
        set_reg(cpu, ANYPS5_QEMU_RIP, 0x100000);
        check_api(cpu, anyps5_qemu_cpu_set_ymm(cpu, 2, old_destination),
                  "seed YMM2 after destruction");
        result = run(cpu, 32);
        require(result.reason == ANYPS5_QEMU_HOST_GATE && result.gate == 42 &&
                result.instructions == 4 && result.rip == 0x100010,
                "recreated CPU executes four actual AVX instructions");
        require(memcmp(data+64, expected, 32) == 0,
                "recreated CPU preserves independent AVX results");
        check_api(cpu, anyps5_qemu_cpu_destroy(cpu), "destroy recreated CPU");
    }
    free(code);
    free(data);
    puts("PASS: native ARM64 TCG AVX256/AVX128/AVX2/F16C/FMA, CPUID/XGETBV/XSAVE/XRSTOR, YMM, host call, syscall, budget, explicit faults and repeated create/destroy");
    return 0;
}
