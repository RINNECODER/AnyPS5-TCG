.intel_syntax noprefix
.section .text
.global anyps5_fragment_fixture
anyps5_fragment_fixture:
.ascii "APS5FRG1"
.long 41
.long 0
.macro entry name
.long \name-anyps5_fragment_fixture
.long \name\()_end-\name
.endm
entry load1
entry load2
entry load4
entry load8
entry load16
entry load32
entry store1
entry store2
entry store4
entry store8
entry store16
entry store32
entry prefix_load
entry prefix_store
entry locked_add
entry cmpxchg16
entry fld_one
entry fst_pop
entry fxsave
entry mask_load
entry mask_store
entry gather
entry rep_copy
entry gate
entry read_then_store
entry fninit
entry mask_load_ps128
entry mask_alias_ps128
entry mask_alias_ps256
entry mask_load_pd128
entry mask_alias_pd128
entry mask_load_pd256
entry mask_alias_pd256
entry mask_load_d128
entry mask_alias_d128
entry mask_load_d256
entry mask_alias_d256
entry mask_load_q128
entry mask_alias_q128
entry mask_load_q256
entry mask_alias_q256
load1: mov al, byte ptr [rdi]
load1_end:
load2: mov ax, word ptr [rdi]
load2_end:
load4: mov eax, dword ptr [rdi]
load4_end:
load8: mov rax, qword ptr [rdi]
load8_end:
load16: movdqu xmm0, xmmword ptr [rdi]
load16_end:
load32: vmovdqu ymm0, ymmword ptr [rdi]
load32_end:
store1: mov byte ptr [rdi], al
store1_end:
store2: mov word ptr [rdi], ax
store2_end:
store4: mov dword ptr [rdi], eax
store4_end:
store8: mov qword ptr [rdi], rax
store8_end:
store16: movdqu xmmword ptr [rdi], xmm0
store16_end:
store32: vmovdqu ymmword ptr [rdi], ymm0
store32_end:
prefix_load:
mov al, byte ptr [rdi]
mov al, byte ptr [rdi+64]
prefix_load_end:
prefix_store:
mov byte ptr [rdi], al
mov byte ptr [rdi+64], al
prefix_store_end:
locked_add: lock add qword ptr [rdi], rax
locked_add_end:
cmpxchg16: lock cmpxchg16b xmmword ptr [rdi]
cmpxchg16_end:
fld_one: fld1
fld_one_end:
fst_pop: fstp qword ptr [rdi]
fst_pop_end:
fxsave: fxsave64 [rdi]
fxsave_end:
mask_load: vmaskmovps ymm0, ymm1, ymmword ptr [rdi]
mask_load_end:
mask_store: vmaskmovps ymmword ptr [rdi], ymm1, ymm0
mask_store_end:
gather: vpgatherdd ymm0, [rdi+ymm2*4], ymm1
gather_end:
rep_copy: rep movsb
rep_copy_end:
gate: nop
gate_end:
read_then_store:
mov al, byte ptr [rdi]
mov byte ptr [rdi], al
read_then_store_end:
fninit: fninit
fninit_end:
mask_load_ps128: vmaskmovps xmm0, xmm1, xmmword ptr [rdi]
mask_load_ps128_end:
mask_alias_ps128: vmaskmovps xmm0, xmm0, xmmword ptr [rdi]
mask_alias_ps128_end:
mask_alias_ps256: vmaskmovps ymm0, ymm0, ymmword ptr [rdi]
mask_alias_ps256_end:
mask_load_pd128: vmaskmovpd xmm0, xmm1, xmmword ptr [rdi]
mask_load_pd128_end:
mask_alias_pd128: vmaskmovpd xmm0, xmm0, xmmword ptr [rdi]
mask_alias_pd128_end:
mask_load_pd256: vmaskmovpd ymm0, ymm1, ymmword ptr [rdi]
mask_load_pd256_end:
mask_alias_pd256: vmaskmovpd ymm0, ymm0, ymmword ptr [rdi]
mask_alias_pd256_end:
mask_load_d128: vpmaskmovd xmm0, xmm1, xmmword ptr [rdi]
mask_load_d128_end:
mask_alias_d128: vpmaskmovd xmm0, xmm0, xmmword ptr [rdi]
mask_alias_d128_end:
mask_load_d256: vpmaskmovd ymm0, ymm1, ymmword ptr [rdi]
mask_load_d256_end:
mask_alias_d256: vpmaskmovd ymm0, ymm0, ymmword ptr [rdi]
mask_alias_d256_end:
mask_load_q128: vpmaskmovq xmm0, xmm1, xmmword ptr [rdi]
mask_load_q128_end:
mask_alias_q128: vpmaskmovq xmm0, xmm0, xmmword ptr [rdi]
mask_alias_q128_end:
mask_load_q256: vpmaskmovq ymm0, ymm1, ymmword ptr [rdi]
mask_load_q256_end:
mask_alias_q256: vpmaskmovq ymm0, ymm0, ymmword ptr [rdi]
mask_alias_q256_end:
