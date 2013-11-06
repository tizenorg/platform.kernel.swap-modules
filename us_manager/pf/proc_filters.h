/*
 *  SWAP uprobe manager
 *  modules/us_manager/pf/proc_filters.h
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


#ifndef _PROC_FILTERS_H
#define _PROC_FILTERS_H

#include <linux/types.h>

struct dentry;
struct task_struct;

struct proc_filter {
	struct task_struct *(*call)(struct proc_filter *self,
				    struct task_struct *task);
	void *data;
	void *priv;
};

#define check_task_f(filter, task) filter->call(filter, task)

struct proc_filter *create_pf_by_dentry(struct dentry *dentry, void *priv);
struct proc_filter *create_pf_by_tgid(pid_t tgid, void *priv);
void free_pf(struct proc_filter *pf);

int check_pf_by_dentry(struct proc_filter *filter, struct dentry *dentry);
int check_pf_by_tgid(struct proc_filter *filter, pid_t tgid);
struct dentry *get_dentry_by_pf(struct proc_filter *filter);

#endif /* _PROC_FILTERS_H */
