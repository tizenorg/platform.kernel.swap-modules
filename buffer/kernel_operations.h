/*
 *  SWAP Buffer Module
 *  modules/buffer/kernel_operations.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP Buffer implement
 *
 */

/* Kernel functions wrap */

#ifndef __KERNEL_OPERATIONS_H__
#define __KERNEL_OPERATIONS_H__

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include "data_types.h"


/* MESSAGES */
#define print_debug(msg, args...) \
	printk(KERN_DEBUG "SWAP_BUFFER DEBUG : " msg, ##args)
#define print_msg(msg, args...)   \
	printk(KERN_INFO "SWAP_BUFFER : " msg, ##args)
#define print_warn(msg, args...)  \
	printk(KERN_WARNING "SWAP_BUFFER WARNING : " msg, ##args)
#define print_err(msg, args...)   \
	printk(KERN_ERR "SWAP_BUFFER ERROR : " msg, ##args)
#define print_crit(msg, args...)  \
	printk(KERN_CRIT "SWAP_BUFFER CRITICAL : " msg, ##args)




/* LOCKS */

/* Spinlocks initialization */
static inline void sync_init(struct sync_t *buffer_sync)
{
	spin_lock_init(&buffer_sync->spinlock);
}

/* Lock spinlock with save flags */
static inline void sync_lock(struct sync_t *buffer_sync)
{
	spin_lock_irqsave(&buffer_sync->spinlock, buffer_sync->flags);
}

/* Unlock spinlock with restore flags */
static inline void sync_unlock(struct sync_t *buffer_sync)
{
	spin_unlock_irqrestore(&buffer_sync->spinlock, buffer_sync->flags);
}

/* Lock spinlock */
static inline void sync_lock_no_flags(struct sync_t *buffer_sync)
{
	spin_lock(&buffer_sync->spinlock);
}

/* Unlock spinlock */
static inline void sync_unlock_no_flags(struct sync_t *buffer_sync)
{
	spin_unlock(&buffer_sync->spinlock);
}

/* Disable preemption and irqs */
static inline void swap_irq_disable(unsigned long *flags)
{
	preempt_disable();
	local_irq_save(*flags);
}

/* Enable preemption and irqs */
static inline void swap_irq_enable(unsigned long *flags)
{
	local_irq_restore(*flags);
	preempt_enable();
}

/* SWAP SUBBUFER */


/* We alloc memory for swap_subbuffer structures with common kmalloc */
#define memory_allocation(memory_size)  kmalloc(memory_size, GFP_KERNEL)
#define memory_free(ptr)                kfree(ptr)

/* For subbuffers themselves, we allocate memory with alloc_pages, so, we have
 * to evaluate required pages order */
#define buffer_allocation(memory_size)                        \
	alloc_pages(GFP_KERNEL, (pages_order_in_subbuffer >= 0) ? \
		pages_order_in_subbuffer :                            \
		get_order_for_alloc_pages(memory_size))

#define buffer_free(ptr, subbuf_size)                         \
	__free_pages(ptr, (pages_order_in_subbuffer >= 0) ?       \
		 pages_order_in_subbuffer :                           \
		 get_order_for_alloc_pages(subbuf_size))

#define buffer_address(buffer_ptr)  page_address(buffer_ptr)
#define set_pages_order_in_subbuffer(memory_size) \
	pages_order_in_subbuffer = get_order_for_alloc_pages(memory_size)

/* Functions for pages allocation */
static inline unsigned int nearest_power_of_two(unsigned int number)
{
	unsigned int result = 0;
	unsigned int two_to_the_power = 1;

	/* If aligned_size == PAGE_SIZE we need only one page, so return 0 */
	if (number == 1)
		return result;

	while (two_to_the_power < number) {
		two_to_the_power <<= 1;
		result++;
	}

	return result;
}

static inline unsigned int get_order_for_alloc_pages(size_t memory_size)
{
	/* First evaluate remainder of the division memory_size by PAGE_SIZE.
	 * If memory_size is divisible by PAGE_SIZE, then remainder equals 0. */
	size_t remainder = (memory_size % PAGE_SIZE) ?
		       (memory_size % PAGE_SIZE) : PAGE_SIZE;

	/* Align memory_size to the PAGE_SIZE. aligned_size >= memory_size */
	size_t aligned_size = memory_size + (PAGE_SIZE - remainder);

	return nearest_power_of_two(aligned_size / PAGE_SIZE);
}

#endif /* __KERNEL_OPERATIONS_H__ */
