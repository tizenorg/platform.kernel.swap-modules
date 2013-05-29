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

#ifndef __SWAP_BUFFER_HEADER_H__
#define __SWAP_BUFFER_HEADER_H__

#include "buffer_description.h"

int swap_buffer_init(size_t subbuffer_size, unsigned int nr_subbuffers,
                     int (*subbuffer_full_callback)(void));

int swap_buffer_uninit(void);
ssize_t swap_buffer_write(size_t size, void* data);

int swap_buffer_get(struct swap_buffer **subbuffer);
int swap_buffer_release(struct swap_buffer **subbuffer);

/* Takes pointer to array of subbuffers pointers. Supposed to be NULL,
 * allocation occures in buf_flush.
 * BE AWARE!!! Function returns:
 * =<0 - IF IT FINISHED UNSUCCESSFUL
 * >0 - count of readable buffers */
int swap_buffer_flush(struct swap_buffer ***subbuffer);

#endif /* __SWAP_BUFFER_HEADER_H__ */
