/*
 *  SWAP Buffer Module
 *  modules/buffer/buffer_queue.h
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

/* SWAP Buffer queues interface */

#ifndef __BUFFER_QUEUE_H__
#define __BUFFER_QUEUE_H__

#include "buffer_description.h"

int buffer_queue_allocation(size_t subbuffer_size, unsigned int subbuffers_count);
void buffer_queue_free(void);
int buffer_queue_reset(void);
void buffer_queue_flush(void);
struct swap_subbuffer *get_from_write_list(size_t size, void **ptr_to_write);
struct swap_subbuffer *get_from_read_list(void);
void add_to_write_list(struct swap_subbuffer *subbuffer);
void add_to_read_list(struct swap_subbuffer *subbuffer);
void add_to_busy_list(struct swap_subbuffer *subbuffer);
int remove_from_busy_list(struct swap_subbuffer *subbuffer);
int get_full_buffers_count(void);

int get_busy_buffers_count(void);
int get_pages_count_in_subbuffer(void);

#endif /* __BUFFER_QUEUE_H__ */
