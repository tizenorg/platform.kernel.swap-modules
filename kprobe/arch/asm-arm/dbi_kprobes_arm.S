/*
 *  Kernel Probes (KProbes)
 *  dbi_kprobes_arm.S
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2002, 2004
 */

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/arch/asm-arm/dbi_kprobes_arm.S
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Samsung Electronics, 2006-2013
 *
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both 
 *              user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module 
 *              for separating core and arch parts
 * 2010-2012    Dmitry Kovalenko <d.kovalenko@samsung.com>,
 *              Nikita Kalyazin <n.kalyazin@samsung.com>
 *              improvement and bugs fixing
 * 2010-2011    Alexander Shirshikov
 *              improvement and bugs fixing
 * 2011-2012    Stanislav Andreev <s.andreev@samsung.com>
 *              improvement and bugs fixing
 * 2012         Vitaliy Cherepanov <v.chereapanov@samsung.com>
 *              improvement and bugs fixing
 * 2012-2013    Vasiliy Ulyanov <v.ulyanov@samsung.com>,
 *              Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *              improvement and bugs fixing
 */


/*
 * Function return probe trampoline:
 * 	- init_kprobes() establishes a probepoint here
 * 	- When the probed function returns, this probe
 * 		causes the handlers to fire
 */
		.global kretprobe_trampoline

kretprobe_trampoline:
		nop
		nop
		mov pc, r14



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




