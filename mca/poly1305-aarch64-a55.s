	.arch armv8-a+crypto
	.file	"poly1305.c"
	.text
	.align	2
	.p2align 4,,15
	.global	poly1305_mac
	.type	poly1305_mac, %function
poly1305_mac:
.LFB3:
	.cfi_startproc
	stp	x29, x30, [sp, -144]!
	.cfi_def_cfa_offset 144
	.cfi_offset 29, -144
	.cfi_offset 30, -136
	asr	w17, w3, 4
	mov	x13, x1
	mov	x29, sp
	str	x19, [sp, 16]
	.cfi_offset 19, -128
	adrp	x4, .LC0
	ldr	q30, [x4, #:lo12:.LC0]
	mov	x1, x2
	ldr	q31, [x0]
	ldp	x12, x11, [x0, 16]
	and	v31.16b, v31.16b, v30.16b
	umov	x9, v31.d[1]
	fmov	x8, d31
	cmp	w17, 0
	ble	.L46
	ins	v31.d[1], x9
	fmov	d30, x8
	add	x16, x2, w17, uxtw 4
	mov	x14, x2
	ins	v30.d[1], x9
	mov	x5, 0
	mov	x6, 0
	mov	w7, 0
	ushr	v31.2d, v31.2d, 2
	umov	x10, v30.d[1]
	umov	x15, v31.d[1]
	add	x15, x15, x15, lsl 2
	.p2align 3,,7
.L15:
	ldp	x2, x4, [x14], 16
	adds	x2, x2, x6
	cset	x0, cs
	adds	x4, x4, x5
	cset	x5, cs
	adds	x0, x0, x4
	cset	x4, cs
	mul	x6, x2, x8
	orr	x5, x5, x4
	umulh	x18, x2, x8
	add	w5, w5, 1
	mul	x19, x0, x15
	add	w5, w5, w7
	umulh	x7, x0, x15
	mul	x30, x2, x10
	adds	x6, x6, x19
	mul	x4, x0, x8
	adc	x18, x18, x7
	umulh	x2, x2, x10
	mul	x7, x15, x5
	adds	x4, x4, x30
	umulh	x0, x0, x8
	umulh	x30, x15, x5
	adc	x0, x0, x2
	adds	x7, x7, x18
	cinc	x2, x30, cs
	adds	x4, x4, x7
	adc	x0, x0, x2
	madd	x0, x5, x8, x0
	and	x2, x0, -4
	and	w7, w0, 3
	add	x0, x2, x0, lsr 2
	adds	x6, x6, x0
	cset	x0, cs
	adds	x0, x0, x4
	mov	x5, x0
	cinc	w7, w7, cs
	cmp	x14, x16
	bne	.L15
	ands	w2, w3, 15
	bne	.L47
.L16:
	adds	x12, x12, x6
	cset	x0, cs
	adds	x11, x11, x5
	cset	x1, cs
	adds	x0, x0, x11
	cset	x2, cs
	mov	x11, x0
	orr	x1, x1, x2
	add	w7, w7, w1
	mov	x1, x12
	cmp	w7, 3
	bls	.L48
.L33:
	adds	x1, x12, 5
	cinc	x11, x0, cs
.L4:
	stp	x1, x11, [x13]
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 144
	.cfi_remember_state
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_def_cfa_offset 0
	ret
	.p2align 2,,3
.L48:
	.cfi_restore_state
	cmn	x12, #6
	ccmn	x0, #1, 0, hi
	ccmp	w7, 3, 0, eq
	bne	.L4
	mov	x0, -1
	b	.L33
	.p2align 2,,3
.L47:
	sub	w17, w17, #1
	add	x1, x1, 16
	add	x1, x1, w17, uxtw 4
.L3:
	str	q31, [sp, 96]
	fmov	d31, x8
	mov	w19, w3
	ins	v31.d[1], x9
	and	x2, x2, 15
	add	x0, sp, 128
	str	w7, [sp, 60]
	stp	x6, x5, [sp, 64]
	str	q31, [sp, 32]
	stp	x13, x12, [sp, 80]
	stp	x11, x10, [sp, 112]
	stp	xzr, xzr, [sp, 128]
	bl	memcpy
	ubfx	x1, x19, 3, 1
	mov	x14, x0
	ubfiz	w3, w19, 3, 3
	mov	x0, 1
	ldr	w7, [sp, 60]
	lsl	x0, x0, x3
	ldr	x2, [x14, x1, lsl 3]
	ldr	q31, [sp, 96]
	orr	x0, x0, x2
	str	x0, [x14, x1, lsl 3]
	ldp	x6, x5, [sp, 64]
	umov	x4, v31.d[1]
	ldp	x3, x0, [sp, 128]
	ldr	q31, [sp, 32]
	ldp	x11, x10, [sp, 112]
	add	x4, x4, x4, lsl 2
	adds	x3, x3, x6
	fmov	x8, d31
	cset	x1, cs
	adds	x2, x0, x5
	cset	x0, cs
	adds	x1, x1, x2
	cset	x2, cs
	orr	x0, x0, x2
	mul	x6, x3, x8
	add	w0, w7, w0
	mul	x7, x1, x4
	umulh	x15, x1, x4
	umulh	x5, x3, x8
	adds	x6, x6, x7
	mul	x14, x3, x10
	mul	x2, x1, x8
	adc	x7, x5, x15
	umulh	x1, x8, x1
	mul	x5, x4, x0
	adds	x2, x2, x14
	umulh	x3, x3, x10
	umulh	x4, x4, x0
	adc	x1, x1, x3
	adds	x5, x5, x7
	cinc	x4, x4, cs
	adds	x2, x2, x5
	adc	x1, x1, x4
	ldp	x13, x12, [sp, 80]
	madd	x0, x0, x8, x1
	and	x1, x0, -4
	and	w7, w0, 3
	add	x0, x1, x0, lsr 2
	adds	x6, x6, x0
	cset	x0, cs
	adds	x0, x0, x2
	mov	x5, x0
	cinc	w7, w7, cs
	b	.L16
	.p2align 2,,3
.L46:
	ands	w2, w3, 15
	bne	.L36
	mov	x1, x12
	b	.L4
.L36:
	ins	v31.d[1], x9
	mov	x5, 0
	mov	x6, 0
	mov	w7, 0
	umov	x10, v31.d[1]
	ushr	v31.2d, v31.2d, 2
	b	.L3
	.cfi_endproc
.LFE3:
	.size	poly1305_mac, .-poly1305_mac
	.section	.rodata.cst16,"aM",@progbits,16
	.align	4
.LC0:
	.xword	1152921487695413247
	.xword	1152921487695413244
	.ident	"GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0"
	.section	.note.GNU-stack,"",@progbits
