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
#include "sspt_page.h"
#include <linux/slab.h>
#include <linux/list.h>
#include <us_slot_manager.h>
#include <us_proc_inst.h>

#define mm_read_lock(task, mm, atomic, lock)			\
	mm = atomic ? task->active_mm : get_task_mm(task); 	\
	if (mm == NULL) {					\
		/* FIXME: */					\
		panic("ERRR mm_read_lock: mm == NULL\n");	\
	}							\
								\
	if (atomic) {						\
		lock = down_read_trylock(&mm->mmap_sem);	\
	} else {						\
		lock = 1;					\
		down_read(&mm->mmap_sem);			\
	}

#define mm_read_unlock(mm, atomic, lock) 			\
	if (lock) {						\
		up_read(&mm->mmap_sem);				\
	}							\
								\
	if (!atomic) {						\
		mmput(mm);					\
	}

static LIST_HEAD(proc_probes_list);

struct sspt_proc *sspt_proc_create(struct dentry* dentry, struct task_struct *task)
{
	struct sspt_proc *proc = kmalloc(sizeof(*proc), GFP_ATOMIC);

	if (proc) {
		INIT_LIST_HEAD(&proc->list);
		proc->tgid = task ? task->tgid : 0;
		proc->task = task;
		proc->dentry = dentry;
		proc->sm = NULL;
		proc->first_install = 0;
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

struct sspt_proc *sspt_proc_get_by_task(struct task_struct *task)
{
	struct sspt_proc *proc, *tmp;

	list_for_each_entry_safe(proc, tmp, &proc_probes_list, list) {
		if (proc->tgid == task->tgid) {
			return proc;
		}
	}

	return NULL;
}

static void add_proc_probes(struct sspt_proc *proc)
{
	list_add_tail(&proc->list, &proc_probes_list);
}

struct sspt_proc *sspt_proc_get_new(struct task_struct *task)
{
	struct sspt_proc *proc;

	proc = sspt_proc_copy(us_proc_info.pp, task);
	proc->sm = create_sm_us(task);
	add_proc_probes(proc);

	return proc;
}

struct sspt_proc *sspt_proc_get_by_task_or_new(struct task_struct *task)
{
	struct sspt_proc *proc = sspt_proc_get_by_task(task);
	if (proc == NULL) {
		proc = sspt_proc_get_new(task);
	}

	return proc;
}

void sspt_proc_free_all(void)
{
	// is user-space instrumentation
	if (us_proc_info.path == NULL) {
		return;
	}

	struct sspt_proc *proc, *n;
	list_for_each_entry_safe(proc, n, &proc_probes_list, list) {
		list_del(&proc->list);
		sspt_proc_free(proc);
	}
}

static void sspt_proc_add_file(struct sspt_proc *proc, struct sspt_file *file)
{
	list_add(&file->list, &proc->file_list);
	file->proc = proc;
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
	struct sspt_proc *proc_out = sspt_proc_create(proc->dentry, task);

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

void sspt_proc_install_page(struct sspt_proc *proc, unsigned long page_addr)
{
	int lock, atomic;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct task_struct *task = proc->task;

	atomic = in_atomic();
	mm_read_lock(task, mm, atomic, lock);

	vma = find_vma(mm, page_addr);
	if (vma && check_vma(vma)) {
		struct dentry *dentry = vma->vm_file->f_dentry;
		struct sspt_file *file = sspt_proc_find_file(proc, dentry);
		if (file) {
			struct sspt_page *page;
			if (!file->loaded) {
				sspt_file_set_mapping(file, vma);
				file->loaded = 1;
			}

			page = sspt_find_page_mapped(file, page_addr);
			if (page) {
				sspt_register_page(page, file);
			}
		}
	}

	mm_read_unlock(mm, atomic, lock);
}

void sspt_proc_install(struct sspt_proc *proc)
{
	int lock, atomic;
	struct vm_area_struct *vma;
	struct task_struct *task = proc->task;
	struct mm_struct *mm;

	proc->first_install = 1;

	atomic = in_atomic();
	mm_read_lock(task, mm, atomic, lock);

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			struct dentry *dentry = vma->vm_file->f_dentry;
			struct sspt_file *file = sspt_proc_find_file(proc, dentry);
			if (file) {
				if (!file->loaded) {
					file->loaded = 1;
					sspt_file_set_mapping(file, vma);
				}

				sspt_file_install(file);
			}
		}
	}

	mm_read_unlock(mm, atomic, lock);
}
