/*
 *  SWAP Writer Module
 *  modules/writer/kernel_operations.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP Writer implementation
 *
 */

/* Kernel functions wrap */

#ifndef __KERNEL_OPERATIONS_H__
#define __KERNEL_OPERATIONS_H__

#include <linux/kernel.h>
#include <asm/ptrace.h>

/* MESSAGES */

#define print_debug(msg, args...) \
	printk(KERN_DEBUG "SWAP_WRITER DEBUG : " msg, ##args)
#define print_msg(msg, args...)   \
	printk(KERN_INFO "SWAP_WRITER : " msg, ##args)
#define print_warn(msg, args...)  \
	printk(KERN_WARNING "SWAP_WRITER WARNING : " msg, ##args)
#define print_err(msg, args...)   \
	printk(KERN_ERR "SWAP_WRITER ERROR : " msg, ##args)
#define print_crit(msg, args...)  \
	printk(KERN_CRIT "SWAP_WRITER CRITICAL : " msg, ##args)

/* ARCH-DEPENDED OPERATIONS */

#if defined(CONFIG_ARM)

#define get_regs_ip(regs)           regs->ARM_pc
#define get_regs_ret_func(regs)     regs->ARM_lr
#define get_regs_ret_val(regs)      regs->ARM_r0
#define get_regs_stack_ptr(regs)    regs->ARM_sp

#elif defined(CONFIG_X86_32)

#define get_regs_ip(regs)           regs->ip - 1
#define get_regs_ret_val(regs)      regs->ax
#define get_regs_stack_ptr(regs)    regs->sp

static inline u32 get_regs_ret_func(struct pt_regs *regs)
{
	u32 *sp, addr = 0;

	if (user_mode(regs)) {
		sp = (u32 *)regs->sp;
		if (get_user(addr, sp))
			printk("failed to dereference a pointer, sp=%p, "
			       "pc=%lx\n", sp, get_regs_ip(regs));
	} else {
		sp = (u32 *)kernel_stack_pointer(regs);
		addr = *sp;
	}

	return addr;
}

#endif /* CONFIG_arch */

int get_args(unsigned long args[], int cnt, struct pt_regs *regs);

#endif /* __KERNEL_OPERATIONS_H__ */
