/*
 *  SWAP driver
 *  modules/driver_new/swap_ioctl.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP device driver implement
 *
 */

#ifndef __SWAP_IOCTL_H__
#define __SWAP_IOCTL_H__

#include <linux/ioctl.h>

#define SWAP_DRIVER_IOC_MAGIC 0xAF

struct buffer_initialize {
	size_t size;
	unsigned int count;
};

/* SWAP Device ioctl commands */

#define SWAP_DRIVER_BUFFER_INITIALIZE		_IOW(SWAP_DRIVER_IOC_MAGIC, 1, \
						     struct buffer_initialize *)
#define SWAP_DRIVER_BUFFER_UNINITIALIZE		_IO(SWAP_DRIVER_IOC_MAGIC, 2)
#define SWAP_DRIVER_NEXT_BUFFER_TO_READ		_IO(SWAP_DRIVER_IOC_MAGIC, 3)
#define SWAP_DRIVER_FLUSH_BUFFER		_IO(SWAP_DRIVER_IOC_MAGIC, 4)
#define SWAP_DRIVER_MSG				_IOW(SWAP_DRIVER_IOC_MAGIC, 5, \
						     void *)

#endif /* __SWAP_IOCTL_H__ */
