/*
 *  SWAP Buffer Module
 *  modules/buffer/swap_buffer_module.h
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

/* SWAP Buffer interface description */

#ifndef __SWAP_BUFFER_MODULE_H__
#define __SWAP_BUFFER_MODULE_H__

#include <linux/types.h>

struct swap_subbuffer;

struct buffer_init_t {
	size_t subbuffer_size;
	unsigned int nr_subbuffers;
	int (*subbuffer_full_cb)(void);

	/* Lower threshold in percent. When buffers fall below this limit
	 * low_mem_cb is called and swap_buffer is suspended. */
	unsigned char lower_threshold;
	int (*low_mem_cb)(void);

	/* Top threshold in percent. When buffers exceed this limit
	 * enough_mem_cb is called */
	unsigned char top_threshold;
	int (*enough_mem_cb)(void);
};

/* SWAP Buffer initialization function. Call it before using buffer.
 * Returns memory pages count (>0) in one subbuffer on success, or error code
 * (<0) otherwise. */
int swap_buffer_init(struct buffer_init_t *buf_init);

/* SWAP Buffer uninitialization function. Call it every time before removing
 * this module. 
 * Returns E_SB_SUCCESS (0) on success, otherwise error code. */
int swap_buffer_uninit(void);

/* SWAP Buffer write function. Pass it size of the data and pointer to the data.
 * On success returns number of bytes written (>=0) or error code (<0) otherwise */
ssize_t swap_buffer_write(void* data, size_t size);

/* SWAP Buffer get. Put subbuffer pointer to the variable *subbuffer. 
 * Return pages count in subbuffer. */
int swap_buffer_get(struct swap_subbuffer **subbuffer);

/* SWAP Buffer release. All 'get' buffers must be released with this function.
 * Just pass &subbuffer_ptr to it */
int swap_buffer_release(struct swap_subbuffer **subbuffer);

/* SWAP Buffer flush. Puts all buffers to read queue and returns their count. */
int swap_buffer_flush(void);

#endif /* __SWAP_BUFFER_MODULE_H__ */
