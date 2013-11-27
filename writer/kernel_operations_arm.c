/*
 *  SWAP Writer
 *  modules/writer/kernel_operations_arm.c
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
#include <asm/uaccess.h>
#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <generated/autoconf.h>

#include "kernel_operations.h"


/* ======================= ARGS ========================== */

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
		unsigned long *args_in_sp = (unsigned long *)regs->ARM_sp +
					    i - stack_args;
		if (get_user(args[i], args_in_sp))
			printk("failed to dereference a pointer, addr=%p\n",
			       args_in_sp);
	}

	return 0;
}


/* ================== KERNEL SHARED MEM ===================== */

/* CONFIG_VECTORS_BASE used to handle both MMU and non-MMU cases.
 * According to docs (Documentation/arm/memory.txt) all vector addresses
 * are fixed and vectors are always equal to one page, so,
 * end = start + PAGE_SIZE
 * */

const char *get_shared_kmem(struct mm_struct *mm, unsigned long *start,
                            unsigned long *end)
{
	*start = CONFIG_VECTORS_BASE;
	*end = CONFIG_VECTORS_BASE + PAGE_SIZE;

	return "[vectors]";
}
