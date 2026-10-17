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
	movl	%ecx, %r11d
	vmovdqa	.LC0(%rip), %xmm0
	movq	%rdx, %r9
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	sarl	$4, %r11d
	movl	%ecx, %r10d
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
	movq	16(%rdi), %rax
	vpand	(%rdi), %xmm0, %xmm0
	movq	24(%rdi), %r13
	movq	%rsi, -64(%rsp)
	movq	%rax, -56(%rsp)
	testl	%r11d, %r11d
	jle	.L47
	vpextrq	$1, %xmm0, -72(%rsp)
	movq	-72(%rsp), %rax
	vpsrlq	$2, %xmm0, %xmm2
	movq	$0, -96(%rsp)
	vpsllq	$2, %xmm2, %xmm1
	movl	%r11d, -32(%rsp)
	vmovq	%xmm0, %rbp
	xorl	%edi, %edi
	movq	%rax, -104(%rsp)
	movslq	%r11d, %rax
	vpaddq	%xmm2, %xmm1, %xmm1
	movq	%rbp, %r14
	salq	$4, %rax
	movq	%rdx, -48(%rsp)
	vpextrq	$1, %xmm1, %rcx
	leaq	(%rdx,%rax), %r12
	movq	%r13, -40(%rsp)
	xorl	%eax, %eax
	movq	%r12, -80(%rsp)
	movl	%r10d, -28(%rsp)
	xorl	%r10d, %r10d
	.p2align 4,,10
	.p2align 3
.L9:
	movq	(%rdx), %r8
	movq	8(%rdx), %rsi
	addq	$16, %rdx
	movq	%rdx, -88(%rsp)
	addq	%r10, %r8
	adcq	%rdi, %rsi
	movq	%r8, %rdx
	mulx	%r14, %r10, %r11
	movq	%rsi, %rdx
	adcl	$1, %eax
	mulx	%rcx, %r12, %r13
	mulx	%r14, %rsi, %rdi
	movq	-104(%rsp), %rdx
	movl	%eax, %eax
	movq	%rax, %rbx
	mulx	%r8, %r8, %r9
	movq	%rcx, %rdx
	addq	%r12, %r10
	adcq	%r13, %r11
	imulq	%rbp, %rbx
	addq	%rsi, %r8
	movq	%r11, %r12
	adcq	%rdi, %r9
	mulx	%rax, %rsi, %rdi
	xorl	%r13d, %r13d
	addq	%r8, %r12
	adcq	%r9, %r13
	movq	-88(%rsp), %rdx
	addq	%rsi, %r12
	adcq	%rdi, %r13
	leaq	0(%r13,%rbx), %rax
	movq	%rax, %rdi
	movq	%rax, %rsi
	shrq	$2, %rdi
	andq	$-4, %rsi
	addq	%rdi, %rsi
	xorl	%edi, %edi
	addq	%rsi, %r10
	setc	%dil
	xorl	%esi, %esi
	addq	%r12, %rdi
	setc	%sil
	andl	$3, %eax
	addl	%esi, %eax
	cmpq	-80(%rsp), %rdx
	jne	.L9
	movq	%r10, %r8
	movl	-28(%rsp), %r10d
	movl	-32(%rsp), %r11d
	movq	%rdi, %rsi
	movq	-48(%rsp), %r9
	movq	-40(%rsp), %r13
	movl	%r10d, %edx
	andl	$15, %edx
	jne	.L48
.L10:
	movq	-56(%rsp), %rdx
	addq	%r8, %rdx
	adcq	%rsi, %r13
	movq	%rdx, %rcx
	adcl	$0, %eax
	movq	%r13, %rbx
	cmpl	$3, %eax
	jbe	.L49
.L21:
	addq	$5, %rdx
	adcq	$0, %r13
	movq	%rdx, %rcx
	movq	%r13, %rbx
.L4:
	movq	-64(%rsp), %rax
	movq	%rcx, (%rax)
	movq	%rbx, 8(%rax)
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
	.p2align 4,,10
	.p2align 3
.L49:
	.cfi_restore_state
	cmpq	$-6, %rdx
	seta	%dil
	cmpq	$-1, %r13
	sete	%sil
	testb	%sil, %dil
	je	.L4
	cmpl	$3, %eax
	jne	.L4
	movq	$-1, %r13
	jmp	.L21
	.p2align 4,,10
	.p2align 3
.L48:
	leal	-1(%r11), %ecx
	salq	$4, %rcx
	leaq	16(%r9,%rcx), %r9
.L3:
	vpxor	%xmm0, %xmm0, %xmm0
	leaq	-24(%rsp), %r11
	movq	%r9, %rcx
	vmovdqa	%xmm0, -24(%rsp)
	cmpl	$8, %edx
	jnb	.L50
.L11:
	xorl	%edi, %edi
	testb	$4, %dl
	jne	.L51
	testb	$2, %dl
	jne	.L52
.L15:
	andl	$1, %edx
	jne	.L53
.L16:
	movl	%r10d, %edx
	andl	$7, %r10d
	movl	$1, %ecx
	sarl	$3, %edx
	sall	$3, %r10d
	vpsllq	$2, %xmm2, %xmm0
	andl	$1, %edx
	shlx	%r10, %rcx, %rcx
	vpaddq	%xmm2, %xmm0, %xmm0
	orq	%rcx, -24(%rsp,%rdx,8)
	addq	-24(%rsp), %r8
	vpextrq	$1, %xmm0, %r15
	adcq	-16(%rsp), %rsi
	movq	%r8, %rdx
	mulx	%rbp, %rcx, %rbx
	movq	%rsi, %r10
	movq	%r15, %rdx
	adcl	$0, %eax
	mulx	%rsi, %rsi, %rdi
	movq	%r10, %rdx
	mulx	%rbp, %r10, %r11
	movq	-72(%rsp), %rdx
	mulx	%r8, %r8, %r9
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rax, %rdi
	imulq	%rbp, %rdi
	addq	%r10, %r8
	adcq	%r11, %r9
	xorl	%r11d, %r11d
	addq	%rbx, %r8
	adcq	%r11, %r9
	mulq	%r15
	addq	%r8, %rax
	adcq	%r9, %rdx
	movq	%rax, %r9
	addq	%rdx, %rdi
	movq	%rdi, %rsi
	movq	%rdi, %rdx
	shrq	$2, %rsi
	andq	$-4, %rdx
	addq	%rsi, %rdx
	xorl	%esi, %esi
	addq	%rdx, %rcx
	setc	%sil
	xorl	%eax, %eax
	movq	%rcx, %r8
	addq	%r9, %rsi
	setc	%al
	andl	$3, %edi
	addl	%edi, %eax
	jmp	.L10
	.p2align 4,,10
	.p2align 3
.L50:
	movl	%edx, %r11d
	xorl	%ecx, %ecx
	andl	$-8, %r11d
.L12:
	movl	%ecx, %edi
	addl	$8, %ecx
	movq	(%r9,%rdi), %rbx
	movq	%rbx, -24(%rsp,%rdi)
	cmpl	%r11d, %ecx
	jb	.L12
	leaq	-24(%rsp,%rcx), %r11
	addq	%r9, %rcx
	jmp	.L11
	.p2align 4,,10
	.p2align 3
.L53:
	movzbl	(%rcx,%rdi), %edx
	movb	%dl, (%r11,%rdi)
	jmp	.L16
	.p2align 4,,10
	.p2align 3
.L52:
	movzwl	(%rcx,%rdi), %r9d
	movw	%r9w, (%r11,%rdi)
	addq	$2, %rdi
	andl	$1, %edx
	je	.L16
	jmp	.L53
	.p2align 4,,10
	.p2align 3
.L51:
	movl	(%rcx), %edi
	movl	%edi, (%r11)
	movl	$4, %edi
	testb	$2, %dl
	je	.L15
	jmp	.L52
	.p2align 4,,10
	.p2align 3
.L47:
	movl	%ecx, %edx
	andl	$15, %edx
	jne	.L24
	movq	%rax, %rcx
	movq	%r13, %rbx
	jmp	.L4
.L24:
	xorl	%esi, %esi
	xorl	%r8d, %r8d
	vmovq	%xmm0, %rbp
	xorl	%eax, %eax
	vpsrlq	$2, %xmm0, %xmm2
	vpextrq	$1, %xmm0, -72(%rsp)
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
