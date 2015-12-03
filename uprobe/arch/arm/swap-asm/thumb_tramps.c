/*
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/string.h>
#include <swap-asm/swap_kprobes.h>
#include "trampoline_thumb.h"


#define URET_BP		0xdeff		/* breakpoint for uretprobe */


static void make_def(void *tramp, unsigned long insn,
		     unsigned long vaddr, bool t2)
{
	unsigned long ret_addr;
	unsigned short *tr = tramp;

	/*
	 * thumb  - +2
	 * thumb2 - +4
	 */
	ret_addr = vaddr + (2 << t2);
	tr[4] = insn & 0x0000ffff;
	if (t2)
		tr[5] = insn >> 16;

	tr[13] = URET_BP;
	tr[16] = (ret_addr & 0x0000ffff) | 0x1;
	tr[17] = ret_addr >> 16;
}

void tt_make_common(void *tramp, unsigned long insn,
		    unsigned long vaddr, bool t2)
{	memcpy(tramp, gen_insn_execbuf_thumb, 4 * UPROBES_TRAMP_LEN);
	make_def(tramp, insn, vaddr, t2);
}

void tt_make_pc_deps(void *tramp, unsigned long mod_insn,
		     unsigned long vaddr, bool t2)
{
	unsigned long pc_val = vaddr + 4;
	unsigned short *tr = tramp;

	memcpy(tramp, pc_dep_insn_execbuf_thumb, 4 * UPROBES_TRAMP_LEN);
	make_def(tramp, mod_insn, vaddr, t2);

	/* save PC value */
	tr[14] = pc_val & 0x0000ffff;
	tr[15] = pc_val >> 16;
}
