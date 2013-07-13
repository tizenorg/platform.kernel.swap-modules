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

#ifdef CONFIG_ARM

#define get_regs_ip(regs)       regs->ARM_pc
#define get_regs_ret_func(regs) regs->ARM_lr
#define get_regs_ret_val(regs)  get_regs_r0(regs)
#define get_regs_r0(regs)       regs->ARM_r0
#define get_regs_r1(regs)       regs->ARM_r1
#define get_regs_r2(regs)       regs->ARM_r2
#define get_regs_r3(regs)       regs->ARM_r3

#elif CONFIG_X86_32

#define get_regs_ip(regs)       regs->ip
//TODO Ret function address for x86!
#define get_regs_ret_func(regs) 0
#define get_regs_ret_val(regs)  0
#define get_regs_r0(regs)       0
#define get_regs_r1(regs)       0
#define get_regs_r2(regs)       0
#define get_regs_r3(regs)       0

#endif /* CONFIG_arch */



#endif /* __KERNEL_OPERATIONS_H__ */
