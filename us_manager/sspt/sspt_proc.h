#ifndef __SSPT_PROC__
#define __SSPT_PROC__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_proc.h
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

struct slot_manager;
struct task_struct;

enum US_FLAGS {
	US_UNREGS_PROBE,
	US_DISARM
};

struct sspt_proc {
	struct list_head list;
	pid_t tgid;
	struct task_struct *task;
	struct slot_manager *sm;
	struct list_head file_list;
	unsigned first_install:1;
	struct sspt_feature *feature;
};


struct sspt_proc *sspt_proc_create(struct task_struct *task, void *priv);
void sspt_proc_free(struct sspt_proc *proc);

void on_each_proc(void (*func)(struct sspt_proc *, void *), void *data);

struct sspt_proc *sspt_proc_get_by_task(struct task_struct *task);
struct sspt_proc *sspt_proc_get_by_task_or_new(struct task_struct *task,
					       void *priv);
void sspt_proc_free_all(void);

struct sspt_file *sspt_proc_find_file(struct sspt_proc *proc, struct dentry *dentry);
struct sspt_file *sspt_proc_find_file_or_new(struct sspt_proc *proc,
					     struct dentry *dentry);

void sspt_proc_install_page(struct sspt_proc *proc, unsigned long page_addr);
void sspt_proc_install(struct sspt_proc *proc);
int sspt_proc_uninstall(struct sspt_proc *proc, struct task_struct *task, enum US_FLAGS flag);

#endif /* __SSPT_PROC__ */
