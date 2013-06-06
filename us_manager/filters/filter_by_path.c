/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/filters/filter_by_path.c
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

#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <us_proc_inst.h>
#include "filters_core.h"
#include <sspt/sspt.h>

struct dentry;
static struct dentry *dentry = NULL;

static int check_dentry(struct task_struct *task, struct dentry *dentry)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = task->mm;

	if (mm == NULL) {
		return 0;
	}

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma) && vma->vm_file->f_dentry == dentry) {
			return 1;
		}
	}

	return 0;
}

static int init_by_path(void *data, size_t size)
{
	if (dentry) {
		return -EPERM;
	}

	dentry = (struct dentry *)data;

	return 0;
}

static void uninit_by_path(void)
{
	dentry = NULL;
}

static struct task_struct *call_by_path(struct task_struct *task)
{
	if (dentry && check_dentry(task, dentry))
		return task;

	return NULL;
}

static struct task_filter ts_filter = {
	.init = init_by_path,
	.uninit = uninit_by_path,
	.call = call_by_path
};

struct task_filter *get_filter_by_path(void)
{
	return &ts_filter;
}
