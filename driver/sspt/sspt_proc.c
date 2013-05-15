/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_proc.c
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

#include "sspt_proc.h"
#include <linux/slab.h>
#include <linux/list.h>

extern struct list_head proc_probes_list;

struct sspt_proc *sspt_proc_create(struct dentry* dentry, pid_t tgid)
{
	struct sspt_proc *proc = kmalloc(sizeof(*proc), GFP_ATOMIC);

	if (proc) {
		INIT_LIST_HEAD(&proc->list);
		proc->tgid = tgid;
		proc->dentry = dentry;
		INIT_LIST_HEAD(&proc->file_list);
	}

	return proc;
}

void sspt_proc_free(struct sspt_proc *proc)
{
	struct sspt_file *file, *n;
	list_for_each_entry_safe(file, n, &proc->file_list, list) {
		list_del(&file->list);
		sspt_file_free(file);
	}

	kfree(proc);
}

// TODO: remove "us_proc_info"
#include "../storage.h"
extern inst_us_proc_t us_proc_info;

void sspt_proc_free_all(void)
{
	// is user-space instrumentation
	if (us_proc_info.path == NULL) {
		return;
	}

	if (strcmp(us_proc_info.path,"*") == 0) {
		// libonly
		struct sspt_proc *proc, *n;
		list_for_each_entry_safe(proc, n, &proc_probes_list, list) {
			list_del(&proc->list);
			sspt_proc_free(proc);
		}
	} else {
		// app
		sspt_proc_free(us_proc_info.pp);
		us_proc_info.pp = NULL;
	}
}

static void sspt_proc_add_file(struct sspt_proc *proc, struct sspt_file *file)
{
	list_add(&file->list, &proc->file_list);
}

struct sspt_file *sspt_proc_find_file_or_new(struct sspt_proc *proc,
		struct dentry *dentry, char *name)
{
	struct sspt_file *file;

	list_for_each_entry(file, &proc->file_list, list) {
		if (file->dentry == dentry) {
			return file;
		}
	}

	file = sspt_file_create(name, dentry, 10);
	sspt_proc_add_file(proc, file);

	return file;
}

void sspt_proc_add_ip_data(struct sspt_proc *proc, struct dentry* dentry,
		char *name, struct ip_data *ip_d)
{
	struct sspt_file *file = sspt_proc_find_file_or_new(proc, dentry, name);
	sspt_file_add_ip(file, ip_d);
}

struct sspt_proc *sspt_proc_copy(struct sspt_proc *proc, struct task_struct *task)
{
	struct sspt_file *file;
	struct sspt_proc *proc_out = sspt_proc_create(proc->dentry, task->tgid);

	list_for_each_entry(file, &proc->file_list, list) {
		sspt_proc_add_file(proc_out, sspt_file_copy(file));
	}

	return proc_out;
}

struct sspt_file *sspt_proc_find_file(struct sspt_proc *proc, struct dentry *dentry)
{
	struct sspt_file *file;

	list_for_each_entry(file, &proc->file_list, list) {
		if (dentry == file->dentry) {
			return file;
		}
	}

	return NULL;
}
