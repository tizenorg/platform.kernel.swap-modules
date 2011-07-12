		.thumb

		.global gen_insn_execbuf_thumb
gen_insn_execbuf_thumb:
		nop
		nop
		nop			// original instruction
		nop			// original instruction
		nop
		nop
		nop
		sub	sp, sp, #8
		str	r0, [sp, #0]
		ldr	r0, [pc, #12]
		str	r0, [sp, #4]
		nop
		pop	{r0, pc}	// ssbreak
		nop			// retbreak
		nop
		nop
		nop			// stored PC-4(next insn addr) hi
		nop			// stored PC-4(next insn addr) lo

		nop

		.global pc_dep_insn_execbuf_thumb
pc_dep_insn_execbuf_thumb:
		push	{r6, r7}
		ldr	r6, i1
		mov	r7, sp
		mov	sp, r6
		nop			// PC -> SP
		nop			// PC -> SP
		mov	sp, r7
		pop	{r6, r7}
		push	{r0, r1}
		ldr	r0, i2
		nop
		str	r0, [sp, #4]
		pop	{r0, pc}	// ssbreak
		nop			// retbreak
		nop			// stored PC hi
i1:		nop			// stored PC lo
		nop			// stored PC-4(next insn addr) hi
i2:		nop			// stored PC-4(next insn addr) lo
