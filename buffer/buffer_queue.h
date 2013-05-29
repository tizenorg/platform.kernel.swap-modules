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

/* SWAP Buffer queues interface */

#ifndef __BUFFER_QUEUE_HEADER__
#define __BUFFER_QUEUE_HEADER__

#include "buffer_description.h"

int buffer_queue_allocation(size_t subbuffer_size, unsigned int subbuffers_count);
int buffer_queue_free(void);
struct swap_buffer* get_from_write_list(size_t size);
struct swap_buffer* get_from_read_list(void);
int add_to_write_list(struct swap_buffer* subbuffer);
int add_to_read_list(struct swap_buffer* subbuffer);
int add_to_busy_list(struct swap_buffer* subbuffer);
int remove_from_busy_list(struct swap_buffer* subbuffer);
int get_full_buffers_count(void);

int set_all_to_read_list(void);
int get_busy_buffers_count(void);
int get_pages_in_subbuffer(void);

#endif /* __BUFFER_QUEUE_HEADER__ */
