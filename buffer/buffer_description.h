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

/* SWAP Buffer structure description */

#ifndef __BUFFER_DESCRIPTION_H__
#define __BUFFER_DESCRIPTION_H__

#include "space_dep_types_and_def.h"

struct swap_buffer {
    struct swap_buffer* next_in_queue;      // Next buffer in queue
    size_t full_buffer_part;                // Buffer length
    swap_subbuffer_ptr buffer;              // Points to subbuffers virt mem(user)
                                            // or to subbuffers first page(kernel)
    buffer_rw_sync_type buffer_sync;        // Buffer sync primitive
};

#endif /* __BUFFER_DESCRIPTION_H__ */
