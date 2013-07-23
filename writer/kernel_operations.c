/*
 *  SWAP Writer
 *  modules/writer/swap_writer_module.c
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

#include <asm/ptrace.h>

#if defined(CONFIG_ARM)

int get_args(unsigned long args[], int cnt, struct pt_regs *regs)
{
	/* All args, except first 4, are passed on the stack */
	enum { stack_args = 4 };
	int i, args_in_regs;

	args_in_regs = cnt < 3 ? cnt : 3;

	/* Get first 4 args from registers */
	switch (args_in_regs) {
		case 3:
			args[3] = regs->ARM_r3;
		case 2:
			args[2] = regs->ARM_r2;
		case 1:
			args[1] = regs->ARM_r1;
		case 0:
			args[0] = regs->ARM_r0;
	}

	/* Get other args from stack */
	for (i = stack_args; i < cnt; ++i) {
		unsigned long *args_in_sp = (unsigned long *)regs->ARM_sp;
		args[i] = args_in_sp[i - stack_args];
	}

	return 0;
}

#elif defined(CONFIG_X86_32)

int get_args(unsigned long args[], int cnt, struct pt_regs *regs)
{
	int i, stack_args = 0;

	/* If we're in kernel mode on x86, get arguments from bx, cx, dx, si,
	 * di, bp
	 */
	if (!user_mode(regs)) {
		int args_in_regs;
		args_in_regs = cnt < 5 ? cnt : 5;
		stack_args = 6;

		switch (args_in_regs) {
			case 5:
				args[5] = regs->bp;
			case 4:
				args[4] = regs->di;
			case 3:
				args[3] = regs->si;
			case 2:
				args[2] = regs->dx;
			case 1:
				args[1] = regs->cx;
			case 0:
				args[0] = regs->bx;
		}
	}

	/* Get other args from stack */
	for (i = stack_args; i < cnt; ++i) {
		unsigned long *args_in_sp = (unsigned long *)regs->sp + 1;
		args[i] = args_in_sp[i - stack_args];
	}

	return 0;
}

#endif /* CONFIG_arch */
