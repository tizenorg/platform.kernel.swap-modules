/*
 *  SWAP Driver Module
 *  modules/buffer/swap_driver_errors.h
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
 * 2013	 Alexander Aksenov <a.aksenov@samsung.com>: SWAP Driver implement
 *
 */

#ifndef __SWAP_DRIVER_ERRORS_H__
#define __SWAP_DRIVER_ERRORS_H__

/* SWAP Driver error codes enumeration */

enum _swap_driver_errors {
	E_SD_SUCCESS = 0,		   /* Success */
	E_SD_ALLOC_CHRDEV_FAIL = 1,	 /* alloc_chrdev_region failed */
	E_SD_CDEV_ALLOC_FAIL = 2,	   /* cdev_alloc failed */
	E_SD_CDEV_ADD_FAIL = 3,	 /* cdev_add failed */
	E_SD_CLASS_CREATE_FAIL = 4,	 /* class_create failed */
	E_SD_DEVICE_CREATE_FAIL = 5,	/* device_create failed */
	E_SD_NO_SPLICE_FUNCS = 6,	   /* splice_* funcs not found */
	E_SD_NO_DATA_TO_READ = 7,	   /* swap_buffer_get tells us that there is no
					   readable subbuffers */
	E_SD_NO_BUSY_SUBBUFFER = 8,	 /* No busy subbuffer */
	E_SD_WRONG_SUBBUFFER_PTR = 9,	/* Wrong subbuffer pointer passed to
					   swap_buffer module */
	E_SD_BUFFER_ERROR = 10,	 /* Unhandled swap_buffer error */
	E_SD_WRITE_ERROR = 11,	  /* Write to subbuffer error */
	E_SD_WRONG_ARGS = 12,	   /* Arguments, passed to the func, doesn't 
					   pass sanity check */
	E_SD_NO_MEMORY = 13,		/* No memory to allocate */
	E_SD_UNINIT_ERROR = 14	  /* swap_buffer uninitialization error */
};

#endif /* __SWAP_DRIVER_ERRORS_H__ */
