/*
 *  SWAP kernel features
 *  driver/swap_debugfs.c
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
 * 2013         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/module.h>
#include <linux/debugfs.h>


static struct dentry *swap_dir = NULL;


struct dentry *get_swap_debugfs_dir(void)
{
	return swap_dir;
}
EXPORT_SYMBOL_GPL(get_swap_debugfs_dir);

int swap_debugfs_init(void)
{
	swap_dir = debugfs_create_dir("swap", NULL);
	if (swap_dir == NULL)
		return -ENOMEM;

	return 0;
}

void swap_debugfs_exit(void)
{
	struct dentry *dir = swap_dir;

	swap_dir = NULL;
	debugfs_remove_recursive(dir);
}
