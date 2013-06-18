/*
 * Function return probe trampoline:
 * 	- init_kprobes() establishes a probepoint here
 * 	- When the probed function returns, this probe
 * 		causes the handlers to fire
 */

		.global gen_insn_execbuf
gen_insn_execbuf:
		nop
		nop
		nop			//original instruction
		nop
		ldr	pc, [pc, #4]	//ssbreak 
		nop			//retbreak
		nop
		nop			//stored PC-4(next insn addr)



		.global pc_dep_insn_execbuf
pc_dep_insn_execbuf:
		str	r0, [sp, #-4]
		ldr	r0, [pc, #12]
		nop			// instruction with replaced PC
		ldr	r0, [sp, #-4]
		ldr	pc, [pc, #4]	//ssbreak
		nop			// retbreak
		nop			// stored PC
		nop			// stored PC-4 (next insn addr)




