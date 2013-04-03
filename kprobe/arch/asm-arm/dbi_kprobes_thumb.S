
/*
 *  Kernel Probes (KProbes)
 *  dbi_kprobes_thumb.S
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
 *  modules/kprobe/arch/asm-arm/dbi_kprobes_thumb.S
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
		.align 4
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
i1:		nop			// stored PC hi
		nop			// stored PC lo
i2:		nop			// stored PC-4(next insn addr) hi
		nop			// stored PC-4(next insn addr) lo
