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

/* Space-depended operations: memory allocations and synchronizations.
 * This makes swap_buffer buildable both as a kernel module and a library. */

#ifdef BUFFER_FOR_USER

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#else /* BUFFER_FOR_USER */

#include <linux/module.h>
#include <linux/slab.h>

unsigned long flags; // Flags for spinlocks

#endif /* BUFFER_FOR_USER */


#include "space_dep_operations.h"



/* For access sync primitives we use pthread_mutex for user space and
 * spin_locks for kernel space */

inline int buffer_access_init(buffer_access_sync_type *buffer_sync)
{
#ifdef BUFFER_FOR_USER
    return pthread_mutex_init(buffer_sync, NULL);
#else /* BUFFER_FOR_USER */
    spin_lock_init(buffer_sync);
    return 0;
#endif /* BUFFER_FOR_USER */
}

inline int buffer_access_lock(buffer_access_sync_type *buffer_sync)
{
#ifdef BUFFER_FOR_USER
    return pthread_mutex_lock(buffer_sync);
#else /* BUFFER_FOR_USER */
    spin_lock_irqsave(buffer_sync, flags);
    return 0;
#endif /* BUFFER_FOR_USER */
}

inline int buffer_access_unlock(buffer_access_sync_type *buffer_sync)
{
#ifdef BUFFER_FOR_USER
    return pthread_mutex_unlock(buffer_sync);
#else /* BUFFER_FOR_USER */
    spin_unlock_irqrestore(buffer_sync, flags);
    return 0;
#endif /* BUFFER_FOR_USER */
}


/* For buffer RW sync primitives in kernel space we use spinlocks as we do it
 * for access sync primitives, so, if building for kernel, buffer_access
 * functions are called. */

inline int buffer_rw_init(buffer_rw_sync_type *buffer_rw)
{
#ifdef BUFFER_FOR_USER
    return sem_init(buffer_rw, 0, 1);
#else /* BUFFER_FOR_USER */
    return buffer_access_init(buffer_rw);
#endif /* BUFFER_FOR_USER */
}

inline int buffer_rw_lock(buffer_rw_sync_type *buffer_rw)
{
#ifdef BUFFER_FOR_USER
    return sem_wait(buffer_rw);
#else /* BUFFER_FOR_USER */
    return buffer_access_lock(buffer_rw);
#endif /* BUFFER_FOR_USER */
}

inline int buffer_rw_unlock(buffer_rw_sync_type *buffer_rw)
{
#ifdef BUFFER_FOR_USER
    return sem_post(buffer_rw);
#else /* BUFFER_FOR_USER */
    return buffer_access_unlock(buffer_rw);
#endif /* BUFFER_FOR_USER */
}

#ifndef BUFFER_FOR_USER

inline unsigned int nearest_power_of_two(unsigned int number)
{
    unsigned int result = 0;
    unsigned int two_to_the_power = 1;

    /* If aligned_size == PAGE_SIZE we need only one page, so return 0 */
    if (number == 1) {
        return result;
    }

    while (two_to_the_power < number) {
        two_to_the_power <<= 1;
        result++;
    }

    return result;
}

inline unsigned int get_order_for_alloc_pages(size_t memory_size)
{
    /* First evaluate remainder of the division memory_size by PAGE_SIZE.
     * If memory_size is divisible by PAGE_SIZE, then remainder equals 0. */
    size_t remainder = (memory_size % PAGE_SIZE) ?
                       (memory_size % PAGE_SIZE) : PAGE_SIZE;

    /* Align memory_size to the PAGE_SIZE. aligned_size >= memory_size */
    size_t aligned_size = memory_size + (PAGE_SIZE - remainder);

    return nearest_power_of_two(aligned_size / PAGE_SIZE);
}

#endif /* BUFFER_FOR_USER */

