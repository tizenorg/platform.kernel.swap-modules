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
		nop
		push	{r7}
		ldr	r7, [pc, #12]
		mov	r9, r7
		pop	{r7}
		mov	pc, r9		// ssbreak
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
		nop
		ldr	r6, i2
		mov	r9, r6
		mov	sp, r7
		pop	{r6, r7}
		nop
		mov	pc, r9		// ssbreak
		nop			// retbreak
		nop			// stored PC hi
i1:		nop			// stored PC lo
		nop			// stored PC-4(next insn addr) hi
i2:		nop			// stored PC-4(next insn addr) lo
