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

/* Space-depended operations file header.
 * This makes swap_buffer buildable both as a kernel module and a library. */

#ifndef __SPACE_DEPENDED_OPERATIONS_FILE_HEADER__
#define __SPACE_DEPENDED_OPERATIONS_FILE_HEADER__

#include "space_dep_types_and_def.h"

inline int buffer_access_init(buffer_access_sync_type *buffer_sync);//Buffer
                                                                    //access 
                                                                    //sync 
                                                                    //primitives
                                                                     //init
inline int buffer_access_lock(buffer_access_sync_type *buffer_sync);//Lock sync
                                                                    //primitive
inline int buffer_access_unlock(buffer_access_sync_type *buffer_sync);//Unlock 
                                                                      //sync
                                                                     //primitive
inline int buffer_rw_init(buffer_rw_sync_type *buffer_rw); //Init read-write 
                                                           //sync primitive
inline int buffer_rw_lock(buffer_rw_sync_type *buffer_rw); //Lock read-write
                                                           //sync primitive
inline int buffer_rw_unlock(buffer_rw_sync_type *buffer_rw); //Unlock read-write
                                                             //sync primitive

#endif /* __SPACE_DEPENDED_OPERATIONS_FILE_HEADER__ */
