/*
 *  SWAP Driver
 *  modules/driver/kernel_operations.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP Driver implement
 *
 */

/* Kernel functions wrap */

#ifndef __KERNEL_OPERATIONS_H__
#define __KERNEL_OPERATIONS_H__

#include <linux/kernel.h>

/* MESSAGES */
#define print_debug(msg, args...) \
	printk(KERN_DEBUG "SWAP_DRIVER DEBUG : " msg, ##args)
#define print_msg(msg, args...)   \
	printk(KERN_INFO "SWAP_DRIVER : " msg, ##args)
#define print_warn(msg, args...)  \
	printk(KERN_WARNING "SWAP_DRIVER WARNING : " msg, ##args)
#define print_err(msg, args...)   \
	printk(KERN_ERR "SWAP_DRIVER ERROR : " msg, ##args)
#define print_crit(msg, args...)  \
	printk(KERN_CRIT "SWAP_DRIVER CRITICAL : " msg, ##args)

#endif /* __KERNEL_OPERATIONS_H__ */
