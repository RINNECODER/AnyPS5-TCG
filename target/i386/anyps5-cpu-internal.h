#ifndef I386_ANYPS5_CPU_INTERNAL_H
#define I386_ANYPS5_CPU_INTERNAL_H

#include "accel/tcg/cpu-ops.h"

void anyps5_qemu_cpu_install_ops(CPUState *cs, TCGCPUOps *ops);
bool anyps5_qemu_cpu_prepare_model(X86CPU *cpu, Error **errp);
bool anyps5_qemu_cpu_intercept_syscall(CPUX86State *env, int next_eip_addend);

#endif
