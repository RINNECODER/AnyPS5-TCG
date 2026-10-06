#ifndef QEMU_ANYPS5_CPU_H
#define QEMU_ANYPS5_CPU_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AnyPS5QemuCpu AnyPS5QemuCpu;
typedef struct AnyPS5QemuContext AnyPS5QemuContext;

enum AnyPS5QemuRegister {
    ANYPS5_QEMU_RAX, ANYPS5_QEMU_RCX, ANYPS5_QEMU_RDX, ANYPS5_QEMU_RBX,
    ANYPS5_QEMU_RSP, ANYPS5_QEMU_RBP, ANYPS5_QEMU_RSI, ANYPS5_QEMU_RDI,
    ANYPS5_QEMU_R8, ANYPS5_QEMU_R9, ANYPS5_QEMU_R10, ANYPS5_QEMU_R11,
    ANYPS5_QEMU_R12, ANYPS5_QEMU_R13, ANYPS5_QEMU_R14, ANYPS5_QEMU_R15,
    ANYPS5_QEMU_RIP, ANYPS5_QEMU_RFLAGS, ANYPS5_QEMU_FS_BASE,
    ANYPS5_QEMU_GS_BASE
};

enum AnyPS5QemuPermission {
    ANYPS5_QEMU_READ = 1,
    ANYPS5_QEMU_WRITE = 2,
    ANYPS5_QEMU_EXECUTE = 4
};

enum AnyPS5QemuStop {
    ANYPS5_QEMU_BUDGET,
    ANYPS5_QEMU_HOST_GATE,
    ANYPS5_QEMU_SYSCALL,
    ANYPS5_QEMU_REQUESTED_STOP,
    ANYPS5_QEMU_FAULT,
    ANYPS5_QEMU_UNSUPPORTED,
    ANYPS5_QEMU_STOP_ADDRESS
};

typedef struct AnyPS5QemuRunResult {
    enum AnyPS5QemuStop reason;
    uint64_t instructions;
    uint64_t rip;
    uint64_t address;
    uint64_t gate;
    uint32_t vector;
    uint32_t error_code;
} AnyPS5QemuRunResult;

AnyPS5QemuCpu *anyps5_qemu_cpu_create(char *error, size_t error_size);
int anyps5_qemu_cpu_destroy(AnyPS5QemuCpu *cpu);
/* Contexts capture supported user registers only, on the idle CPU owner.
 * Creation captures the current state. Save replaces that snapshot; restore
 * does not change the process profile, mappings, gates or stop request.
 * Contexts belong to their creating CPU. A destroyed context is rejected while
 * that CPU remains alive. CPU destruction expires the CPU and every context
 * pointer; callers must not pass any of those pointers to this API afterward.
 */
int anyps5_qemu_cpu_context_create(AnyPS5QemuCpu *cpu,
                                 AnyPS5QemuContext **context);
int anyps5_qemu_cpu_context_save(AnyPS5QemuCpu *cpu, AnyPS5QemuContext *context);
int anyps5_qemu_cpu_context_restore(AnyPS5QemuCpu *cpu,
                                  const AnyPS5QemuContext *context);
int anyps5_qemu_cpu_context_destroy(AnyPS5QemuCpu *cpu,
                                  AnyPS5QemuContext *context);
int anyps5_qemu_cpu_map_borrowed(AnyPS5QemuCpu *cpu, uint64_t address,
                               void *backing, size_t size, unsigned permissions);
/* Register the full stable, host-page-aligned allocation once, then alias it. */
int anyps5_qemu_cpu_register_backing(AnyPS5QemuCpu *cpu, void *backing,
                                   size_t allocated_size, uint64_t *id);
int anyps5_qemu_cpu_release_backing(AnyPS5QemuCpu *cpu, uint64_t id);
int anyps5_qemu_cpu_map_alias(AnyPS5QemuCpu *cpu, uint64_t address,
                            uint64_t backing_id, size_t offset, size_t size,
                            unsigned permissions);
int anyps5_qemu_cpu_unmap(AnyPS5QemuCpu *cpu, uint64_t address);
/* Atomically remove covered logical pages, retaining both outside fragments. */
int anyps5_qemu_cpu_unmap_range(AnyPS5QemuCpu *cpu, uint64_t address, size_t size);
/* Replace fully covered pages (including PROT_NONE) with one backing alias.
 * Rejected ranges, holes, backing extents or capacity leave all mappings intact.
 * Backing registration/lifetime follows map_alias; unrelated gates are retained.
 */
int anyps5_qemu_cpu_replace_alias(AnyPS5QemuCpu *cpu, uint64_t address,
                                uint64_t backing_id, size_t offset, size_t size,
                                unsigned permissions);
int anyps5_qemu_cpu_protect(AnyPS5QemuCpu *cpu, uint64_t address,
                          unsigned permissions);
int anyps5_qemu_cpu_protect_range(AnyPS5QemuCpu *cpu, uint64_t address,
                                size_t size, unsigned permissions);
/* Host writes bypass guest dirty tracking; call before executing changed code. */
int anyps5_qemu_cpu_invalidate(AnyPS5QemuCpu *cpu);
int anyps5_qemu_cpu_get(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg,
                       uint64_t *value);
int anyps5_qemu_cpu_set(AnyPS5QemuCpu *cpu, enum AnyPS5QemuRegister reg,
                       uint64_t value);
int anyps5_qemu_cpu_get_ymm(AnyPS5QemuCpu *cpu, unsigned reg, void *value);
int anyps5_qemu_cpu_set_ymm(AnyPS5QemuCpu *cpu, unsigned reg, const void *value);
int anyps5_qemu_cpu_add_gate(AnyPS5QemuCpu *cpu, uint64_t address, uint64_t id);
int anyps5_qemu_cpu_run(AnyPS5QemuCpu *cpu, uint64_t instruction_budget,
                       AnyPS5QemuRunResult *result);
int anyps5_qemu_cpu_run_until(AnyPS5QemuCpu *cpu, uint64_t instruction_budget,
                            uint64_t until, AnyPS5QemuRunResult *result);
void anyps5_qemu_cpu_stop(AnyPS5QemuCpu *cpu);
int anyps5_qemu_cpu_clear_stop(AnyPS5QemuCpu *cpu);
const char *anyps5_qemu_cpu_error(AnyPS5QemuCpu *cpu);

#ifdef __cplusplus
}
#endif

#endif
