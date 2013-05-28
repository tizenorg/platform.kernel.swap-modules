/*
 *  SWAP Buffer Module
 *  modules/buffer/swap_buffer_module.c
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
 * 2013         Alexander Aksenov <a.aksenov@samsung.com>: SWAP Buffer implement
 *
 */

/* Space-depended types and defines.
 * This makes swap_buffer buildable both as a kernel module and as a library.*/

#ifndef __SPACE_DEPENDEND_TYPES_AND_DEFINES_FILE_HEADER__
#define __SPACE_DEPENDEND_TYPES_AND_DEFINES_FILE_HEADER__

#ifdef BUFFER_FOR_USER

#include <semaphore.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#else /* BUFFER_FOR_USER */

#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#endif /*BUFFER_FOR_USER */


/* Functions for alloc_pages */
#ifndef BUFFER_FOR_USER

inline unsigned int nearest_power_of_two(unsigned int number);
inline unsigned int get_order_for_alloc_pages(size_t memory_size);

#endif /* BUFFER_FOR_USER */



/* Synchronization primitives with the same interface for different context */
#ifdef BUFFER_FOR_USER

typedef sem_t buffer_rw_sync_type;              // Read-write sync
typedef pthread_mutex_t buffer_access_sync_type;// Pointer manipulations sync

#else /* BUFFER_FOR_USER */

typedef spinlock_t buffer_rw_sync_type;         // Read-write sync
typedef spinlock_t buffer_access_sync_type;     // Pointer manipulations sync

#endif /*BUFFER_FOR_USER */


/* Subbuffer type */
#ifdef BUFFER_FOR_USER

typedef void* swap_subbuffer_ptr;

#else /* BUFFER_FOR_USER */

/* If buffer supposed to work in kernel space, it's very useful to
 * store buffer page struct ptr */
typedef struct page* swap_subbuffer_ptr;

#endif /* BUFFER_FOR_USER */


/* Memory and buffer operations */
#ifdef BUFFER_FOR_USER

#define memory_allocation(memory_size)  malloc(memory_size)
#define memory_free(ptr)                free(ptr)
#define buffer_allocation(memory_size)  malloc(memory_size)
#define buffer_free(ptr, subbuf_size)   free(ptr)
#define buffer_address(buffer_ptr)      buffer_ptr

#else /* BUFFER_FOR_USER */

#define memory_allocation(memory_size)  kmalloc(memory_size, GFP_KERNEL)
#define memory_free(ptr)                kfree(ptr)
#define buffer_allocation(memory_size)                        \
    alloc_pages(GFP_KERNEL, (pages_order_in_subbuffer >= 0) ? \
                pages_order_in_subbuffer :                    \
                get_order_for_alloc_pages(memory_size))
#define buffer_free(ptr, subbuf_size)                         \
    __free_pages(ptr, (pages_order_in_subbuffer >= 0) ?       \
                 pages_order_in_subbuffer :                   \
                 get_order_for_alloc_pages(subbuf_size))
// TODO Check whether it is correct for several pages
#define buffer_address(buffer_ptr)      page_address(buffer_ptr)

#endif /* BUFFER_FOR_USER */


/* Set pages_order_in_subbuffer variable. Used only in kernel space */
#ifdef BUFFER_FOR_USER

#define set_pages_order_in_subbuffer(memory_size) \
    pages_order_in_subbuffer = 0

#else /* BUFFER_FOR_USER */

#define set_pages_order_in_subbuffer(memory_size) \
    pages_order_in_subbuffer = get_order_for_alloc_pages(memory_size)

#endif /* BUFFER_FOR_USER */


/* Kernel module specific functions */
#ifdef BUFFER_FOR_USER

#define SWAP_BUFFER_MODULE_INFORMATION 

#else /* BUFFER_FOR_USER */

#define SWAP_BUFFER_MODULE_INFORMATION \
static int __init swap_buffer_module_init(void)                         \
{                                                                       \
    printk(KERN_NOTICE "SWAP_BUFFER : Buffer module initialized\n");    \
    return 0;                                                           \
}                                                                       \
                                                                        \
static void __exit swap_buffer_module_exit(void)                        \
{                                                                       \
    printk(KERN_NOTICE "SWAP_BUFFER : Buffer module unintialized\n");   \
}                                                                       \
                                                                        \
module_init(swap_buffer_module_init);                                   \
module_exit(swap_buffer_module_exit);

#endif /* BUFFER_FOR_USER */


/* Message printing */
#ifdef BUFFER_FOR_USER

#define print_debug(msg, args...) \
    printf("SWAP_BUFFER DEBUG : " msg, ##args)
#define print_msg(msg, args...)   \
    printf("SWAP_BUFFER : " msg, ##args)
#define print_warn(msg, args...)  \
    printf("SWAP_BUFFER WARNING : " msg, ##args)
#define print_err(msg, args...)   \
    printf("SWAP_BUFFER ERROR : " msg, ##args)
#define print_crit(msg, args...)  \
    printf("SWAP_BUFFER CRITICAL : " msg, ##args)

#else /* BUFFER_FOR_USER */

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

#endif /* BUFFER_FOR_USER */

#endif /* __SPACE_DEPENDEND_TYPES_AND_DEFINES_FILE_HEADER__ */
