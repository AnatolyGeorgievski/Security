	.arm
	.global UADD
UADD:
	stmfd	sp!, { r4, r5, r6, r7, lr }

	ldmia	r1!, { r6, r7, ip, lr }
	ldmia	r0 , { r2, r3, r4, r5 }
	adds	r2, r2, r6
	adcs	r3, r3, r7
	adcs	r4, r4, ip
	adcs	r5, r5, lr
	stmia	r0!, { r2, r3, r4, r5 }

	ldmia	r1!, { r6, r7, ip, lr }
	ldmia	r0 , { r2, r3, r4, r5 }
	adcs	r2, r2, r6
	adcs	r3, r3, r7
	adcs	r4, r4, ip
	adcs	r5, r5, lr
	stmia	r0!, { r2, r3, r4, r5 }

	ldmfd	sp!, { r4, r5, r6, r7, pc }
