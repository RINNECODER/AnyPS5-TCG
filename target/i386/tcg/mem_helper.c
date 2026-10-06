/*
 *  x86 memory access helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "qemu/int128.h"
#include "qemu/atomic128.h"
#include "tcg/tcg.h"
#include "helper-tcg.h"
#include "access.h"

void helper_probe_store(CPUX86State *env, target_ulong address, uint32_t size,
                        uint32_t alignment)
{
    X86Access access;

    if (alignment && (address & (alignment - 1))) {
        handle_unaligned_access(env, address, MMU_DATA_STORE, GETPC());
    }
    /* Resolve both pages before a composite store writes its first part. */
    access_prepare(&access, env, address, size, MMU_DATA_STORE, GETPC());
}

void helper_masked_load(CPUX86State *env, void *destination, void *mask_pointer,
                        target_ulong address, uint32_t element_size,
                        uint32_t vector_size)
{
    const ZMMReg *mask = mask_pointer;
    ZMMReg result = {0};
    uintptr_t ra = GETPC();

    assert((element_size == 4 || element_size == 8) &&
           (vector_size == 16 || vector_size == 32));
    /* Inactive lanes never access memory. Stage all selected reads before
     * destination writes, including when the destination aliases its mask.
     */
    for (unsigned i = 0; i < vector_size / element_size; i++) {
        if (element_size == 4) {
            if (mask->ZMM_L(i) >> 31) {
                result.ZMM_L(i) = cpu_ldl_data_ra(env, address + i * 4, ra);
            }
        } else if (mask->ZMM_Q(i) >> 63) {
            result.ZMM_Q(i) = cpu_ldq_data_ra(env, address + i * 8, ra);
        }
    }
    if (vector_size == 16) {
        memcpy(destination, &result.ZMM_X(0), 16);
    } else {
        memcpy(destination, &result.ZMM_Y(0), 32);
    }
}

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data_ra(env, a0, GETPC());
    high = cpu_ldsw_data_ra(env, a0 + 2, GETPC());
    v = (int16_t)v;
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data_ra(env, a0, GETPC());
    high = cpu_ldl_data_ra(env, a0 + 4, GETPC());
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}
