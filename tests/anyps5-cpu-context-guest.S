.text
.global _start
_start:
    fninit
    fldcw 64(%rdi)
    fldl 0(%rdi)
    fldl 8(%rdi)
    fld1
    fdivl 24(%rdi)
    fstpl 32(%rdi)
    ldmxcsr 72(%rdi)
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    vmovups (96 + 32 * \reg)(%rdi), %ymm\reg
    .endr
    cvttss2si %xmm0, %eax
    jmp .Linitialized
.org 0x200
.Linitialized:
    nop

.macro continuation endpoint
    movq %rax, 0(%rsi)
    movq %rcx, 8(%rsi)
    movq %rdx, 16(%rsi)
    movq %rbx, 24(%rsi)
    movq %rsp, 32(%rsi)
    movq %rbp, 40(%rsi)
    movq %rsi, 48(%rsi)
    movq %rdi, 56(%rsi)
    movq %r8, 64(%rsi)
    movq %r9, 72(%rsi)
    movq %r10, 80(%rsi)
    movq %r11, 88(%rsi)
    movq %r12, 96(%rsi)
    movq %r13, 104(%rsi)
    movq %r14, 112(%rsi)
    movq %r15, 120(%rsi)
    pushfq
    popq %rax
    movq %rax, 128(%rsi)
    jc 1f
    movl $0xb2, %eax
    jmp 2f
1:
    movl $0xa1, %eax
2:
    movl %eax, 224(%rsi)
    cld
    movq %fs:0, %rax
    movq %rax, 136(%rsi)
    movq %gs:0, %rax
    movq %rax, 144(%rsi)
    stmxcsr 192(%rsi)
    fnstenv 800(%rsi)
    fldenv 800(%rsi)
    .irp reg,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    vaddps %ymm\reg, %ymm\reg, %ymm\reg
    vmovups %ymm\reg, (256 + 32 * \reg)(%rsi)
    .endr
    cvtss2si %xmm0, %rax
    movq %rax, 200(%rsi)
    stmxcsr 196(%rsi)
    faddp %st, %st(1)
    fistpq 152(%rsi)
    fnstcw 208(%rsi)
    fnstsw %ax
    movw %ax, 210(%rsi)
    jmp \endpoint
.endm

.org 0x300
    continuation .LendA
.org 0x800
    continuation .LendB
.org 0xf00
.LendA:
    nop
.org 0xf10
.LendB:
    nop
