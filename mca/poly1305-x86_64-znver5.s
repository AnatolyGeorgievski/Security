	.file	"poly1305.c"
	.text
	.p2align 4
	.globl	poly1305_mac
	.type	poly1305_mac, @function
poly1305_mac:
.LFB3:
	.cfi_startproc
	endbr64
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	movq	24(%rdi), %rbx
	movl	%ecx, %r14d
	sarl	$4, %r14d
	vmovq	%rsi, %xmm3
	vmovdqa	.LC0(%rip), %xmm0
	movq	16(%rdi), %r15
	vpandq	(%rdi), %xmm0, %xmm0
	movq	%rdx, %r12
	movq	%rbx, -56(%rsp)
	movl	%ecx, %r13d
	testl	%r14d, %r14d
	jle	.L47
	vpextrq	$1, %xmm0, -64(%rsp)
	movq	-64(%rsp), %rax
	movq	$0, -80(%rsp)
	movl	%r14d, -32(%rsp)
	movq	%r12, -48(%rsp)
	movq	%r15, -40(%rsp)
	movl	%r13d, -28(%rsp)
	movslq	%r14d, %rbx
	vpsrlq	$2, %xmm0, %xmm2
	vmovq	%xmm0, %rbp
	vpsllq	$2, %xmm2, %xmm1
	vpaddq	%xmm2, %xmm1, %xmm1
	salq	$4, %rbx
	vpextrq	$1, %xmm1, %r9
	vmovq	%xmm0, -72(%rsp)
	movq	%rax, -88(%rsp)
	leaq	(%rdx,%rbx), %r10
	movq	%rdx, %r8
	xorl	%edi, %edi
	xorl	%esi, %esi
	xorl	%edx, %edx
	movq	%rbp, %rcx
	.p2align 4
	.p2align 3
.L9:
	movq	(%r8), %r11
	movq	8(%r8), %rax
	addq	$16, %r8
	addq	%rdi, %r11
	adcq	%rdx, %rax
	movq	%r11, %rdx
	mulx	%rcx, %r12, %r13
	adcl	$1, %esi
	movq	%rax, %rdx
	mulx	%r9, %rdi, %rbp
	movl	%esi, %edx
	movq	-72(%rsp), %rsi
	addq	%r12, %rdi
	adcq	%r13, %rbp
	mulx	%r9, %r14, %r15
	xorl	%r13d, %r13d
	movq	%rbp, %r12
	imulq	%rdx, %rsi
	addq	%r14, %r12
	adcq	%r15, %r13
	mulq	%rcx
	vmovq	%rax, %xmm4
	vpinsrq	$1, %rdx, %xmm4, %xmm4
	movq	-88(%rsp), %rdx
	vmovq	%xmm4, %rax
	mulx	%r11, %r14, %r15
	vpextrq	$1, %xmm4, %rdx
	addq	%r14, %rax
	adcq	%r15, %rdx
	addq	%r12, %rax
	adcq	%r13, %rdx
	movq	%rax, %r14
	addq	%rdx, %rsi
	movq	%rsi, %rdx
	shrq	$2, %rdx
	movq	%rsi, %r11
	andq	$-4, %r11
	addq	%r11, %rdx
	addq	%rdx, %rdi
	setc	%dl
	xorl	%eax, %eax
	movzbl	%dl, %edx
	addq	%r14, %rdx
	setc	%al
	andl	$3, %esi
	addl	%eax, %esi
	cmpq	%r10, %r8
	jne	.L9
	movl	-28(%rsp), %r13d
	movl	-32(%rsp), %r14d
	movq	-48(%rsp), %r12
	movq	-40(%rsp), %r15
	movq	-72(%rsp), %rbp
	movq	%rdx, %rax
	movl	%r13d, %ecx
	andl	$15, %ecx
	jne	.L48
.L10:
	movq	-56(%rsp), %rcx
	addq	%rdi, %r15
	adcq	%rax, %rcx
	movq	%r15, %rax
	adcl	$0, %esi
	movq	%rcx, %rdx
	cmpl	$3, %esi
	jbe	.L49
.L21:
	addq	$5, %r15
	adcq	$0, %rcx
	movq	%r15, %rax
	movq	%rcx, %rdx
.L4:
	vmovq	%xmm3, %rbx
	movq	%rax, (%rbx)
	movq	%rdx, 8(%rbx)
	popq	%rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.p2align 4
	.p2align 3
.L49:
	.cfi_restore_state
	cmpq	$-6, %r15
	seta	%dil
	cmpq	$-1, %rcx
	sete	%cl
	testb	%cl, %dil
	je	.L4
	cmpl	$3, %esi
	jne	.L4
	movq	$-1, %rcx
	jmp	.L21
	.p2align 4
	.p2align 3
.L48:
	leal	-1(%r14), %edx
	salq	$4, %rdx
	leaq	16(%r12,%rdx), %r12
.L3:
	vpxor	%xmm0, %xmm0, %xmm0
	leaq	-24(%rsp), %r9
	movq	%r12, %rdx
	vmovdqa	%xmm0, -24(%rsp)
	cmpl	$8, %ecx
	jnb	.L50
.L11:
	xorl	%r8d, %r8d
	testb	$4, %cl
	jne	.L51
	testb	$2, %cl
	jne	.L52
.L15:
	andl	$1, %ecx
	jne	.L53
.L16:
	movl	%r13d, %edx
	sarl	$3, %edx
	vpsllq	$2, %xmm2, %xmm0
	vpaddq	%xmm2, %xmm0, %xmm0
	andl	$7, %r13d
	andl	$1, %edx
	movl	$1, %ecx
	sall	$3, %r13d
	shlx	%r13, %rcx, %rcx
	orq	%rcx, -24(%rsp,%rdx,8)
	addq	-24(%rsp), %rdi
	adcq	-16(%rsp), %rax
	movq	%rdi, %rdx
	movq	%rax, %rcx
	mulx	%rbp, %r8, %r9
	adcl	$0, %esi
	vpextrq	$1, %xmm0, %rax
	movq	%rcx, %rdx
	mulx	%rax, %r10, %r11
	movq	%rsi, %rdx
	addq	%r10, %r8
	adcq	%r11, %r9
	imulq	%rbp, %rdx
	movq	%rdx, %r14
	movq	%rcx, %rdx
	mulx	%rbp, %rcx, %rbx
	movq	-64(%rsp), %rdx
	mulx	%rdi, %rdi, %rbp
	movq	%rax, %rdx
	addq	%rdi, %rcx
	adcq	%rbp, %rbx
	mulx	%rsi, %rsi, %rdi
	xorl	%r11d, %r11d
	addq	%r9, %rsi
	adcq	%r11, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	leaq	(%r14,%rbx), %rdx
	movq	%rdx, %rsi
	shrq	$2, %rsi
	movq	%rdx, %rax
	andq	$-4, %rax
	addq	%rsi, %rax
	addq	%rax, %r8
	setc	%al
	xorl	%esi, %esi
	movq	%r8, %rdi
	movzbl	%al, %eax
	addq	%rcx, %rax
	setc	%sil
	andl	$3, %edx
	addl	%edx, %esi
	jmp	.L10
	.p2align 4
	.p2align 3
.L50:
	movl	%ecx, %r9d
	andl	$-8, %r9d
	xorl	%edx, %edx
.L12:
	movl	%edx, %r8d
	addl	$8, %edx
	movq	(%r12,%r8), %r10
	movq	%r10, -24(%rsp,%r8)
	cmpl	%r9d, %edx
	jb	.L12
	leaq	-24(%rsp,%rdx), %r9
	addq	%r12, %rdx
	jmp	.L11
	.p2align 4
	.p2align 3
.L53:
	movzbl	(%rdx,%r8), %edx
	movb	%dl, (%r9,%r8)
	jmp	.L16
	.p2align 4
	.p2align 3
.L52:
	movzwl	(%rdx,%r8), %r10d
	movw	%r10w, (%r9,%r8)
	addq	$2, %r8
	andl	$1, %ecx
	je	.L16
	jmp	.L53
	.p2align 4
	.p2align 3
.L51:
	movl	(%rdx), %r8d
	movl	%r8d, (%r9)
	movl	$4, %r8d
	testb	$2, %cl
	je	.L15
	jmp	.L52
	.p2align 4
	.p2align 3
.L47:
	andl	$15, %ecx
	jne	.L24
	movq	%r15, %rax
	movq	%rbx, %rdx
	jmp	.L4
.L24:
	xorl	%eax, %eax
	xorl	%edi, %edi
	xorl	%esi, %esi
	vmovq	%xmm0, %rbp
	vpextrq	$1, %xmm0, -64(%rsp)
	vpsrlq	$2, %xmm0, %xmm2
	jmp	.L3
	.cfi_endproc
.LFE3:
	.size	poly1305_mac, .-poly1305_mac
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC0:
	.quad	1152921487695413247
	.quad	1152921487695413244
	.ident	"GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
