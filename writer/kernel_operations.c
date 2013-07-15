/*
 *  SWAP Writer
 *  modules/driver_new/swap_writer_module.c
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
 * Copyright (C) Samsung Electronics, 2013
 *
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP Writer module kernel
 * operaions implement
 *
 */

#include "kernel_operations.h"

int get_args(unsigned long args[], int cnt, struct pt_regs *regs)
{
	int i, arg_in_regs, stack_args;

	arg_in_regs = cnt < 3 ? cnt : 3;

#if defined(CONFIG_ARM)

	/* All args, except first 4, are passed on the stack */
	stack_args = 4;

	/* Get first 4 args from registers */
	switch (arg_in_regs) {
		case 3:
			args[3] = get_regs_r3(regs);
		case 2:
			args[2] = get_regs_r2(regs);
		case 1:
			args[1] = get_regs_r1(regs);
		case 0:
			args[0] = get_regs_r0(regs);
	}


#elif defined(CONFIG_X86_32)
	if (user_mode(regs)) {
		/* If we're in user mode on x86 arch, get arguments from stack */
		/* ONLY CDECL CALLING CONVENTION IS SUPPORTED RIGHT NOW */
		stack_args = 0;
	} else {
		stack_args = 6;
		/* If we're in kernel mode on x86, get arguments from bx, cx, dx, si,
		 * di, bp */
		switch (arg_in_regs) {
			case 5:
				args[5] = get_regs_bp(regs);
			case 4:
				args[4] = get_regs_di(regs);
			case 3:
				args[3] = get_regs_si(regs);
			case 2:
				args[2] = get_regs_dx(regs);
			case 1:
				args[1] = get_regs_cx(regs);
			case 0:
				args[0] = get_regs_bx(regs);
		}
	}

#endif /* CONFIG_arch */

	/* Get other args from stack */
	for (i = stack_args; i < cnt; ++i) {
		args[i] = *(unsigned long *)(get_regs_stack_ptr(regs) + 
				     ((i- stack_args) * sizeof(unsigned long)));
	}

	return 0;
}
