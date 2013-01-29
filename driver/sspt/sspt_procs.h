#ifndef __SSPT_PROC__
#define __SSPT_PROC__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_procs.h
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

#include <linux/types.h>
#include "sspt_file.h"

struct sspt_procs {
	struct list_head list;
	pid_t tgid;
	struct dentry *dentry;
	struct list_head file_list;
};


struct sspt_procs *sspt_procs_create(struct dentry* dentry, pid_t tgid);
struct sspt_procs *sspt_procs_copy(struct sspt_procs *procs, struct task_struct *task);
void sspt_procs_free(struct sspt_procs *procs);
void sspt_procs_free_all(void);

void proc_p_add_dentry_probes(struct sspt_procs *procs, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt);
struct sspt_file *proc_p_find_file_p_by_dentry(struct sspt_procs *procs,
		const char *pach, struct dentry *dentry);
struct sspt_file *sspt_procs_find_file(struct sspt_procs *procs, struct vm_area_struct *vma);

#endif /* __SSPT_PROC__ */
