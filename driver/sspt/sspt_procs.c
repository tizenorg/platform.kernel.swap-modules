/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_procs.c
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

#include "sspt_procs.h"
#include <linux/slab.h>
#include <linux/list.h>

extern struct list_head proc_probes_list;

struct sspt_procs *sspt_procs_create(struct dentry* dentry, pid_t tgid)
{
	struct sspt_procs *procs = kmalloc(sizeof(*procs), GFP_ATOMIC);

	if (procs) {
		INIT_LIST_HEAD(&procs->list);
		procs->tgid = tgid;
		procs->dentry = dentry;
		INIT_LIST_HEAD(&procs->file_list);
	}

	return procs;
}

void sspt_procs_free(struct sspt_procs *procs)
{
	struct sspt_file *file, *n;
	list_for_each_entry_safe(file, n, &procs->file_list, list) {
		list_del(&file->list);
		sspt_file_free(file);
	}

	kfree(procs);
}

// TODO: remove "us_proc_info"
#include "../storage.h"
extern inst_us_proc_t us_proc_info;

void sspt_procs_free_all(void)
{
	if (strcmp(us_proc_info.path,"*") == 0) {
		// app
		sspt_procs_free(us_proc_info.pp);
		us_proc_info.pp = NULL;
	} else {
		// libonly
		struct sspt_procs *procs, *n;
		list_for_each_entry_safe(procs, n, &proc_probes_list, list) {
			list_del(&procs->list);
			sspt_procs_free(procs);
		}
	}
}

static void sspt_procs_add_file(struct sspt_procs *procs, struct sspt_file *file)
{
	list_add(&file->list, &procs->file_list);
}

struct sspt_file *proc_p_find_file_p_by_dentry(struct sspt_procs *procs,
		const char *pach, struct dentry *dentry)
{
	struct sspt_file *file;

	list_for_each_entry(file, &procs->file_list, list) {
		if (file->dentry == dentry) {
			return file;
		}
	}

	file = sspt_file_create(pach, dentry, 10);
	sspt_procs_add_file(procs, file);

	return file;
}

void proc_p_add_dentry_probes(struct sspt_procs *procs, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt)
{
	int i;
	struct sspt_file *file = proc_p_find_file_p_by_dentry(procs, pach, dentry);

	for (i = 0; i < cnt; ++i) {
		sspt_file_add_ip(file, &ip_d[i]);
	}
}

struct sspt_procs *sspt_procs_copy(struct sspt_procs *procs, struct task_struct *task)
{
	struct sspt_file *file;
	struct sspt_procs *procs_out = sspt_procs_create(procs->dentry, task->tgid);

	list_for_each_entry(file, &procs->file_list, list) {
		sspt_procs_add_file(procs_out, sspt_file_copy(file));
	}

	return procs_out;
}

struct sspt_file *sspt_procs_find_file(struct sspt_procs *procs, struct vm_area_struct *vma)
{
	struct sspt_file *file;

	list_for_each_entry(file, &procs->file_list, list) {
		if (vma->vm_file->f_dentry == file->dentry) {
			return file;
		}
	}

	return NULL;
}
