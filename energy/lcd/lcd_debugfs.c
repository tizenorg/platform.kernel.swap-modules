/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  energy/lcd/lcd_debugfs.c
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


#include <linux/debugfs.h>
#include <linux/export.h>
#include <energy/lcd/lcd_base.h>
#include <energy/rational_debugfs.h>


static int get_system(void *data, u64 *val)
{
	/* TODO: implement */

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_get_system, get_system, NULL, "%llu\n");


static struct dentry *lcd_dir = NULL;

int register_lcd_debugfs(struct lcd_ops *ops)
{
	int ret;
	struct dentry *dentry, *system;

	if (lcd_dir == NULL)
		return -EINVAL;

	dentry = debugfs_create_dir(ops->name, lcd_dir);
	if (dentry == NULL)
		return -ENOMEM;

	ret = create_rational_files(dentry, &ops->min_coef,
				    "min_num", "min_denom");
	if (ret)
		goto fail;

	ret = create_rational_files(dentry, &ops->max_coef,
				    "max_num", "max_denom");
	if (ret)
		goto fail;

	system = debugfs_create_file("system", 0600, dentry, (void *)ops,
				     &fops_get_system);
	if (system == NULL)
		goto fail;

	ops->dentry = dentry;

	return 0;
fail:
	debugfs_remove_recursive(dentry);
	return -ENOMEM;
}

void unregister_lcd_debugfs(struct lcd_ops *ops)
{
	debugfs_remove_recursive(ops->dentry);
}

void exit_lcd_debugfs(void)
{
	if (lcd_dir)
		debugfs_remove_recursive(lcd_dir);

	lcd_dir = NULL;
}

int init_lcd_debugfs(struct dentry *energy_dir)
{
	lcd_dir = debugfs_create_dir("lcd", energy_dir);
	if (lcd_dir == NULL)
		return -ENOMEM;

	return 0;
}
