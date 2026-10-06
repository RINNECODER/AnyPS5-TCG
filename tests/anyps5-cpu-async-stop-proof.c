#include "qemu/anyps5-cpu.h"
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct StopRequest {
    AnyPS5QemuCpu *cpu;
    atomic_bool started;
    long delay_ns;
} StopRequest;

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

static uint64_t get_reg(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg)
{
    uint64_t value = 0;
    check_api(cpu, anyps5_qemu_cpu_get(cpu, reg, &value), "read register");
    return value;
}

static void *request_stop(void *opaque)
{
    StopRequest *request = opaque;
    struct timespec remaining = {0, request->delay_ns};

    while (!atomic_load_explicit(&request->started, memory_order_acquire)) {
        sched_yield();
    }
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {
    }
    anyps5_qemu_cpu_stop(request->cpu);
    return NULL;
}

int main(void)
{
    const uint64_t entry = UINT64_C(0x100000);
    const uint8_t loop[] = {0x48, 0xff, 0xc0, 0xeb, 0xfb};
    char error[256] = {0};
    const long page = sysconf(_SC_PAGESIZE);
    uint8_t *code = NULL;
    AnyPS5QemuCpu *cpu;
    unsigned active_stops = 0;

    require(page > 0 && posix_memalign((void **)&code, (size_t)page,
                                     (size_t)page) == 0,
            "allocate aligned executable backing");
    memset(code, 0, (size_t)page);
    memcpy(code, loop, sizeof(loop));
    cpu = anyps5_qemu_cpu_create(error, sizeof(error));
    if (!cpu) {
        fprintf(stderr, "FAIL: create CPU: %s\n", error);
        return 1;
    }
    check_api(cpu, anyps5_qemu_cpu_map_borrowed(cpu, entry, code,
              (size_t)page, ANYPS5_QEMU_READ | ANYPS5_QEMU_EXECUTE),
              "map actual x86 increment/branch loop");

    for (unsigned trial = 0; trial < 64; trial++) {
        pthread_t stopper;
        StopRequest request = {.cpu = cpu,
            .delay_ns = 100000L + (long)(trial % 8) * 100000L};
        AnyPS5QemuRunResult result;
        uint64_t before_resume, stopped_pc;

        atomic_init(&request.started, false);
        check_api(cpu, anyps5_qemu_cpu_clear_stop(cpu), "clear prior stop");
        check_api(cpu, anyps5_qemu_cpu_set(cpu, ANYPS5_QEMU_RIP, entry),
                  "set loop PC");
        check_api(cpu, anyps5_qemu_cpu_set(cpu, ANYPS5_QEMU_RAX, 0),
                  "reset independently observed loop counter");
        require(pthread_create(&stopper, NULL, request_stop, &request) == 0,
                "create independent stop thread");
        atomic_store_explicit(&request.started, true, memory_order_release);
        const int run_result = anyps5_qemu_cpu_run(cpu, UINT64_C(100000000),
                                                  &result);
        require(pthread_join(stopper, NULL) == 0,
                "join stopper before reading state or retiring CPU");
        check_api(cpu, run_result, "run asynchronously interrupted guest");
        if (result.reason != ANYPS5_QEMU_REQUESTED_STOP) {
            fprintf(stderr,
                    "FAIL: external stop misclassified trial=%u reason=%u "
                    "vector=%u instructions=%llu rip=0x%llx rax=%llu\n",
                    trial, result.reason, result.vector,
                    (unsigned long long)result.instructions,
                    (unsigned long long)result.rip,
                    (unsigned long long)get_reg(cpu, ANYPS5_QEMU_RAX));
            return 1;
        }
        before_resume = get_reg(cpu, ANYPS5_QEMU_RAX);
        stopped_pc = get_reg(cpu, ANYPS5_QEMU_RIP);
        require(stopped_pc == entry || stopped_pc == entry + 3,
                "external stop preserves an actual instruction boundary");
        active_stops += before_resume != 0;
        check_api(cpu, anyps5_qemu_cpu_clear_stop(cpu),
                  "clear stopped execution for explicit owner resume");
        check_api(cpu, anyps5_qemu_cpu_run(cpu, 500, &result),
                  "resume actual guest after external stop");
        require(result.reason == ANYPS5_QEMU_BUDGET &&
                result.instructions == 500 && result.rip == stopped_pc &&
                get_reg(cpu, ANYPS5_QEMU_RAX) == before_resume + 250,
                "external stop/clear preserves executable continuation");
    }
    require(active_stops != 0,
            "cross-thread stop occurred after real guest execution began");
    check_api(cpu, anyps5_qemu_cpu_destroy(cpu), "destroy on idle owner");
    free(code);
    printf("PASS: 64 external stops, %u after actual x86 progress, "
           "and exact loop continuation after clear\n", active_stops);
    return 0;
}
