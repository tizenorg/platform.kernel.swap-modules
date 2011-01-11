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
		nop			//original instruction
		nop
		push	{r7}
		ldr	r7, [pc, #12]	//ssbreak
		mov	lr, r7
		pop	{r7}
		mov	pc, lr
		nop			//retbreak
		nop
		nop
		nop			//stored PC-4(next insn addr) hi
		nop			//stored PC-4(next insn addr) lo


@ NOT YET READY
		.global pc_dep_insn_execbuf_thumb
pc_dep_insn_execbuf_thumb:
		mov	r1, sp
		mov	r2, #2
		rsb	r2, r2, #0	// r2 = (0 - r2)
		str	r0, [r1, r2]
		ldr	r0, [pc, #12]							// RECALC !!111
		nop			// instruction with replaced PC
		mov	r1, sp
		mov	r2, #4
		rsb	r2, r2, #0
		ldr	r0, [r1, r2]
		ldr	r0, [pc, #4]	//ssbreak					// RECALC !!111
		mov	lr, r0
		mov	pc, lr

		nop			// retbreak
		nop			// stored PC
		nop			// stored PC-4 (next insn addr)


