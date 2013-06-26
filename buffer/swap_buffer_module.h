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

#include "buffer_description.h"

/* SWAP Buffer initialization function. Call it before using buffer.
 * Returns memory pages count (>0) in one subbuffer on success, or error code
 * (<0) otherwise. */
int swap_buffer_init(size_t subbuffer_size, unsigned int nr_subbuffers,
		     int (*subbuffer_full_callback)(void));

/* SWAP Buffer uninitialization function. Call it every time before removing
 * this module. 
 * Returns E_SB_SUCCESS (0) on success, otherwise error code. */
int swap_buffer_uninit(void);

/* SWAP Buffer write function. Pass it size of the data and pointer to the data.
 * On success returns number of bytes written (>=0) or error code (<0) otherwise */
ssize_t swap_buffer_write(size_t size, void* data);

/* SWAP Buffer get. Put subbuffer pointer to the variable *subbuffer. 
 * Return pages count in subbuffer. */
int swap_buffer_get(struct swap_subbuffer **subbuffer);

/* SWAP Buffer release. All 'get' buffers must be released with this function.
 * Just pass &subbuffer_ptr to it */
int swap_buffer_release(struct swap_subbuffer **subbuffer);

/* SWAP Buffer flush. Puts all buffers to read queue and returns their count. */
int swap_buffer_flush(void);

#endif /* __SWAP_BUFFER_MODULE_H__ */
