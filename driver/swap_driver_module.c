/*
 *  SWAP Driver
 *  modules/driver/swap_driver_module.c
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

#include <linux/module.h>

#include "driver_defs.h"
#include "device_driver.h"
#include "swap_debugfs.h"
#include "us_interaction.h"

static int __init swap_driver_init(void)
{
	int ret;

	ret = swap_debugfs_init();
	if (ret)
		return ret;

	ret = swap_device_init();
	if (ret)
		goto dev_init_fail;

	ret = us_interaction_create();
	if (ret)
		goto interact_create_fail;

	print_msg("Driver module initialized\n");

	return 0;

dev_init_fail:
	swap_debugfs_exit();
interact_create_fail:
	swap_device_exit();

	return ret;
}

static void __exit swap_driver_exit(void)
{
	us_interaction_destroy();
	swap_device_exit();
	swap_debugfs_exit();
	print_msg("Driver module uninitialized\n");
}

module_init(swap_driver_init);
module_exit(swap_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP device driver");
MODULE_AUTHOR("Aksenov A.S.");
