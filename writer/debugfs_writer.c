/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  writer/debugfs_writer.c
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
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <driver/swap_debugfs.h>
#include "swap_writer_module.h"


/* ============================================================================
 * ===                               BUFFER                                 ===
 * ============================================================================
 */
static char *buf = NULL;
enum { buf_size = 64*1024*1024 };

static int init_buffer(void)
{
	buf = vmalloc(buf_size);

	return buf ? 0 : -ENOMEM;
}

static void exit_buffer(void)
{
	vfree(buf);
	buf = NULL;
}





/* ============================================================================
 * ===                             FOPS_RAW                                 ===
 * ============================================================================
 */
static ssize_t write_raw(struct file *file, const char __user *user_buf,
			 size_t count, loff_t *ppos)
{
	if (count > buf_size)
		return -EINVAL;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	return raw_msg(buf, count);
}

static const struct file_operations fops_raw = {
	.write =	write_raw,
	.llseek =	default_llseek
};





/* ============================================================================
 * ===                              INIT/EXIT                               ===
 * ============================================================================
 */
static struct dentry *writer_dir = NULL;

void exit_debugfs_writer(void)
{
	if (writer_dir)
		debugfs_remove_recursive(writer_dir);

	writer_dir = NULL;

	exit_buffer();
}

int init_debugfs_writer(void)
{
	int ret;
	struct dentry *swap_dir, *dentry;

	ret = init_buffer();
	if (ret)
		return ret;

	swap_dir = get_swap_debugfs_dir();
	if (swap_dir == NULL)
		return -ENOENT;

	writer_dir = debugfs_create_dir("writer", swap_dir);
	if (writer_dir == NULL)
		return -ENOMEM;

	dentry = debugfs_create_file("raw", 0600, writer_dir, NULL, &fops_raw);
	if (dentry == NULL) {
		exit_debugfs_writer();
		return -ENOMEM;
	}

	return 0;
}
