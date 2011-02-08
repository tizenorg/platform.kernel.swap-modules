/*
 * Function return probe trampoline:
 * 	- init_kprobes() establishes a probepoint here
 * 	- When the probed function returns, this probe
 * 		causes the handlers to fire
 */

		.thumb


		.global gen_insn_execbuf_thumb
gen_insn_execbuf_thumb:
		nop
		nop
		nop			// original instruction
		nop
		nop
		nop
		push	{r7}
		ldr	r7, [pc, #12]
		mov	ip, r7
		pop	{r7}
		mov	pc, ip		// ssbreak
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
		ldr	r6, i2
		mov	ip, r6
		mov	sp, r7
		pop	{r6, r7}
		nop
		mov	pc, ip		// ssbreak
		nop			// retbreak
		nop			// stored PC hi
i1:		nop			// stored PC lo
		nop			// stored PC-4(next insn addr) hi
i2:		nop			// stored PC-4(next insn addr) lo
