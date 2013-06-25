/*
 *  SWAP Buffer Module
 *  modules/buffer/buffer_description.h
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

/* SWAP Buffer structure description */

#ifndef __BUFFER_DESCRIPTION_H__
#define __BUFFER_DESCRIPTION_H__

#include "kernel_operations.h"

struct swap_subbuffer {
	/* Pointer to the next subbuffer in queue */
	struct swap_subbuffer *next_in_queue;
	/* Size of the filled part of a subbuffer */
	size_t full_buffer_part;
	/* Pointer to data buffer */
	swap_subbuffer_ptr data_buffer;
	/* Buffer rw sync */
	struct sync_t buffer_sync;
};

#endif /* __BUFFER_DESCRIPTION_H__ */
