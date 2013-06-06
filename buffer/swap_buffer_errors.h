/*
 *  SWAP Buffer Module
 *  modules/buffer/swap_buffer_errors.h
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

/* SWAP Buffer error codes enumeration */

enum _swap_buffer_errors {
    E_SB_SUCCESS = 0,               /* Succes */
    E_SB_UNRELEASED_BUFFERS = -1,   /* There are some unreleased buffers. Mainly
                                       returned by swap_buffer_uninit */
    E_SB_NO_WRITABLE_BUFFERS = -2,  /* No buffers for writing */
    E_SB_WRONG_DATA_SIZE = -3,      /* Wrong data size: size == 0 or
                                       size > subbuffer size */
    E_SB_IS_STOPPED = -4,           /* Trying to write data after SWAP buffer
                                       has been stopped. */
    E_SB_OVERLAP = -5,              /* Memory areas of data to be written and
                                       subbuffer itself are overlap */
    E_SB_NO_READABLE_BUFFERS = -6,  /* No buffers for reading */
    E_SB_NO_CALLBACK = -7,          /* Callback function ptr == NULL */

    E_SB_NO_MEM_QUEUE_BUSY = -8,    /* Memory for queue_busy wasn't allocated */
    E_SB_NO_MEM_BUFFER_STRUCT = -9, /* Memory for one of struct swap_buffer
                                       wasn't allocated */
    E_SB_NO_MEM_DATA_BUFFER = -10,  /* Memort for data buffer itself wasn't
                                       allocated */
    E_SB_NO_SUBBUFFER_IN_BUSY = -11 /* No such subbuffer in busy_list */
};
