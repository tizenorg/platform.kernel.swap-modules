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
		push	{r7}
		ldr	r7, [pc, #12]	// ssbreak
		mov	lr, r7
		pop	{r7}
		mov	pc, lr
		nop			// retbreak
		nop
		nop
		nop			// stored PC-4(next insn addr) hi
		nop			// stored PC-4(next insn addr) lo
