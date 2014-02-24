/*
 *  SWAP uprobe manager
 *  modules/us_manager/pf/proc_filters.c
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
 * 2013	 Vyacheslav Cherkashin: SWAP us_manager implement
 *
 */


#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include "proc_filters.h"
#include <us_manager/sspt/sspt.h>

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

static struct task_struct *call_by_dentry(struct proc_filter *self,
					 struct task_struct *task)
{
	struct dentry *dentry = (struct dentry *)self->data;

	if (!dentry || check_dentry(task, dentry))
		return task;

	return NULL;
}

static struct task_struct *call_by_tgid(struct proc_filter *self,
				       struct task_struct *task)
{
	pid_t tgid = (pid_t)self->data;

	if (task->tgid == tgid)
		return task;

	return NULL;
}

/* Dumb call. Each task is exactly what we are looking for :) */
static struct task_struct *call_dumb(struct proc_filter *self,
				     struct task_struct *task)
{
	return task;
}

static struct proc_filter *create_pf(void)
{
	struct proc_filter *pf = kmalloc(sizeof(*pf), GFP_KERNEL);

	return pf;
}

struct proc_filter *create_pf_by_dentry(struct dentry *dentry, void *priv)
{
	struct proc_filter *pf = create_pf();

	pf->call = &call_by_dentry;
	pf->data = (void *)dentry;
	pf->priv = priv;

	return pf;
}
struct proc_filter *create_pf_by_tgid(pid_t tgid, void *priv)
{
	struct proc_filter *pf = create_pf();

	pf->call = &call_by_tgid;
	pf->data = (void *)tgid;
	pf->priv = priv;

	return pf;
}

struct proc_filter *create_pf_dumb(void *priv)
{
	struct proc_filter *pf = create_pf();

	pf->call = &call_dumb;
	pf->data = NULL;
	pf->priv = priv;

	return pf;
}

void free_pf(struct proc_filter *pf)
{
	kfree(pf);
}

int check_pf_by_dentry(struct proc_filter *filter, struct dentry *dentry)
{
	return filter->data == (void *)dentry &&
	       filter->call == &call_by_dentry;
}

int check_pf_by_tgid(struct proc_filter *filter, pid_t tgid)
{
	return filter->data == (void *)tgid && filter->call == &call_by_tgid;
}

int check_pf_dumb(struct proc_filter *filter)
{
	return filter->call == &call_dumb;
}

struct dentry *get_dentry_by_pf(struct proc_filter *filter)
{
	if (filter->call == &call_by_dentry)
		return (struct dentry *)filter->data;

	return NULL;
}
