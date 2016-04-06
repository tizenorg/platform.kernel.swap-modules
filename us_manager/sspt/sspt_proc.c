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

#include "sspt.h"
#include "sspt_proc.h"
#include "sspt_page.h"
#include "sspt_feature.h"
#include "sspt_filter.h"
#include "../pf/proc_filters.h"
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <kprobe/swap_ktd.h>
#include <us_manager/us_slot_manager.h>

static LIST_HEAD(proc_probes_list);
static DEFINE_RWLOCK(sspt_proc_rwlock);


struct list_head *sspt_proc_list()
{
	return &proc_probes_list;
}

/**
 * @brief Global read lock for sspt_proc
 *
 * @return Void
 */
void sspt_proc_read_lock(void)
{
	read_lock(&sspt_proc_rwlock);
}

/**
 * @brief Global read unlock for sspt_proc
 *
 * @return Void
 */
void sspt_proc_read_unlock(void)
{
	read_unlock(&sspt_proc_rwlock);
}

/**
 * @brief Global write lock for sspt_proc
 *
 * @return Void
 */
void sspt_proc_write_lock(void)
{
	write_lock(&sspt_proc_rwlock);
}

/**
 * @brief Global write unlock for sspt_proc
 *
 * @return Void
 */
void sspt_proc_write_unlock(void)
{
	write_unlock(&sspt_proc_rwlock);
}


static void ktd_init(struct task_struct *task, void *data)
{
	struct sspt_proc **pproc = (struct sspt_proc **)data;

	*pproc = NULL;
}

static void ktd_exit(struct task_struct *task, void *data)
{
	struct sspt_proc **pproc = (struct sspt_proc **)data;

	WARN_ON(*pproc);
}

struct ktask_data ktd = {
	.init = ktd_init,
	.exit = ktd_exit,
	.size = sizeof(struct sspt_proc *),
};

static struct sspt_proc **pproc_by_task(struct task_struct *task)
{
	return (struct sspt_proc **)swap_ktd(&ktd, task);
}

int sspt_proc_init(void)
{
	return swap_ktd_reg(&ktd);
}

void sspt_proc_uninit(void)
{
	swap_ktd_unreg(&ktd);
}

void sspt_change_leader(struct task_struct *prev, struct task_struct *next)
{
	struct sspt_proc **prev_pproc;

	prev_pproc = pproc_by_task(prev);
	if (*prev_pproc) {
		struct sspt_proc **next_pproc;

		next_pproc = pproc_by_task(next);
		get_task_struct(next);

		/* Change the keeper sspt_proc */
		BUG_ON(*next_pproc);
		*next_pproc = *prev_pproc;
		*prev_pproc = NULL;

		/* Set new the task leader to sspt_proc */
		(*next_pproc)->leader = next;

		put_task_struct(prev);
	}
}

void sspt_reset_proc(struct task_struct *task)
{
	struct sspt_proc **pproc;

	pproc = pproc_by_task(task->group_leader);
	*pproc = NULL;
}





static struct sspt_proc *sspt_proc_create(struct task_struct *leader)
{
	struct sspt_proc *proc = kzalloc(sizeof(*proc), GFP_KERNEL);

	if (proc) {
		proc->feature = sspt_create_feature();
		if (proc->feature == NULL) {
			kfree(proc);
			return NULL;
		}

		INIT_LIST_HEAD(&proc->list);
		proc->tgid = leader->tgid;
		proc->leader = leader;
		/* FIXME: change the task leader */
		proc->sm = create_sm_us(leader);
		INIT_LIST_HEAD(&proc->file_head);
		mutex_init(&proc->filters.mtx);
		INIT_LIST_HEAD(&proc->filters.head);
		atomic_set(&proc->usage, 1);

		get_task_struct(proc->leader);

		proc->suspect.after_exec = 1;
		proc->suspect.after_fork = 0;
	}

	return proc;
}

/**
 * @brief Remove sspt_proc struct
 *
 * @param proc remove object
 * @return Void
 */

/* called with sspt_proc_write_lock() */
void sspt_proc_cleanup(struct sspt_proc *proc)
{
	struct sspt_file *file, *n;

	sspt_proc_del_all_filters(proc);

	list_for_each_entry_safe(file, n, &proc->file_head, list) {
		list_del(&file->list);
		sspt_file_free(file);
	}

	sspt_destroy_feature(proc->feature);

	free_sm_us(proc->sm);
	sspt_proc_put(proc);
}

struct sspt_proc *sspt_proc_get(struct sspt_proc *proc)
{
	atomic_inc(&proc->usage);

	return proc;
}

void sspt_proc_put(struct sspt_proc *proc)
{
	if (atomic_dec_and_test(&proc->usage)) {
		if (proc->__mm) {
			mmput(proc->__mm);
			proc->__mm = NULL;
		}
		if (proc->__task) {
			put_task_struct(proc->__task);
			proc->__task = NULL;
		}

		put_task_struct(proc->leader);
		kfree(proc);
	}
}

struct sspt_proc *sspt_proc_by_task(struct task_struct *task)
{
	return *pproc_by_task(task->group_leader);
}
EXPORT_SYMBOL_GPL(sspt_proc_by_task);

/**
 * @brief Call func() on each proc (no lock)
 *
 * @param func Callback
 * @param data Data for callback
 * @return Void
 */
void on_each_proc_no_lock(void (*func)(struct sspt_proc *, void *), void *data)
{
	struct sspt_proc *proc, *tmp;

	list_for_each_entry_safe(proc, tmp, &proc_probes_list, list) {
		func(proc, data);
	}
}

/**
 * @brief Call func() on each proc
 *
 * @param func Callback
 * @param data Data for callback
 * @return Void
 */
void on_each_proc(void (*func)(struct sspt_proc *, void *), void *data)
{
	sspt_proc_read_lock();
	on_each_proc_no_lock(func, data);
	sspt_proc_read_unlock();
}
EXPORT_SYMBOL_GPL(on_each_proc);

/**
 * @brief Get sspt_proc by task or create sspt_proc
 *
 * @param task Pointer on the task_struct struct
 * @param priv Private data
 * @return Pointer on the sspt_proc struct
 */
struct sspt_proc *sspt_proc_get_by_task_or_new(struct task_struct *task)
{
	static DEFINE_MUTEX(local_mutex);
	struct sspt_proc **pproc;
	struct task_struct *leader = task->group_leader;

	pproc = pproc_by_task(leader);
	if (*pproc)
		goto out;

	/* This lock for synchronizing to create sspt_proc */
	mutex_lock(&local_mutex);
	pproc = pproc_by_task(leader);
	if (*pproc == NULL) {
		*pproc = sspt_proc_create(leader);
		if (*pproc) {
			sspt_proc_write_lock();
			list_add(&(*pproc)->list, &proc_probes_list);
			sspt_proc_write_unlock();
		}
	}
	mutex_unlock(&local_mutex);

out:
	return *pproc;
}

/**
 * @brief Free all sspt_proc
 *
 * @return Pointer on the sspt_proc struct
 */
void sspt_proc_free_all(void)
{
	struct sspt_proc *proc, *n;

	list_for_each_entry_safe(proc, n, &proc_probes_list, list) {
		list_del(&proc->list);
		sspt_proc_cleanup(proc);
	}
}

static void sspt_proc_add_file(struct sspt_proc *proc, struct sspt_file *file)
{
	list_add(&file->list, &proc->file_head);
	file->proc = proc;
}

/**
 * @brief Get sspt_file from sspt_proc by dentry or new
 *
 * @param proc Pointer on the sspt_proc struct
 * @param dentry Dentry of file
 * @return Pointer on the sspt_file struct
 */
struct sspt_file *sspt_proc_find_file_or_new(struct sspt_proc *proc,
					     struct dentry *dentry)
{
	struct sspt_file *file;

	file = sspt_proc_find_file(proc, dentry);
	if (file == NULL) {
		file = sspt_file_create(dentry, 10);
		if (file)
			sspt_proc_add_file(proc, file);
	}

	return file;
}

/**
 * @brief Get sspt_file from sspt_proc by dentry
 *
 * @param proc Pointer on the sspt_proc struct
 * @param dentry Dentry of file
 * @return Pointer on the sspt_file struct
 */
struct sspt_file *sspt_proc_find_file(struct sspt_proc *proc,
				      struct dentry *dentry)
{
	struct sspt_file *file;

	list_for_each_entry(file, &proc->file_head, list) {
		if (dentry == file->dentry)
			return file;
	}

	return NULL;
}

/**
 * @brief Install probes on the page to monitored process
 *
 * @param proc Pointer on the sspt_proc struct
 * @param page_addr Page address
 * @return Void
 */
void sspt_proc_install_page(struct sspt_proc *proc, unsigned long page_addr)
{
	struct mm_struct *mm = proc->leader->mm;
	struct vm_area_struct *vma;

	vma = find_vma_intersection(mm, page_addr, page_addr + 1);
	if (vma && check_vma(vma)) {
		struct dentry *dentry = vma->vm_file->f_dentry;
		struct sspt_file *file = sspt_proc_find_file(proc, dentry);
		if (file) {
			struct sspt_page *page;

			sspt_file_set_mapping(file, vma);

			page = sspt_find_page_mapped(file, page_addr);
			if (page)
				sspt_register_page(page, file);
		}
	}
}

/**
 * @brief Install probes to monitored process
 *
 * @param proc Pointer on the sspt_proc struct
 * @return Void
 */
void sspt_proc_install(struct sspt_proc *proc)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = proc->leader->mm;

	proc->first_install = 1;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			struct dentry *dentry = vma->vm_file->f_dentry;
			struct sspt_file *file =
				sspt_proc_find_file(proc, dentry);
			if (file) {
				sspt_file_set_mapping(file, vma);
				sspt_file_install(file);
			}
		}
	}
}

/**
 * @brief Uninstall probes to monitored process
 *
 * @param proc Pointer on the sspt_proc struct
 * @param task Pointer on the task_struct struct
 * @param flag Action for probes
 * @return Error code
 */
int sspt_proc_uninstall(struct sspt_proc *proc,
			struct task_struct *task,
			enum US_FLAGS flag)
{
	int err = 0;
	struct sspt_file *file;

	list_for_each_entry_rcu(file, &proc->file_head, list) {
		err = sspt_file_uninstall(file, task, flag);
		if (err != 0) {
			printk(KERN_INFO "ERROR sspt_proc_uninstall: err=%d\n",
			       err);
			return err;
		}
	}

	return err;
}

static int intersection(unsigned long start_a, unsigned long end_a,
			unsigned long start_b, unsigned long end_b)
{
	return start_a < start_b ?
			end_a > start_b :
			start_a < end_b;
}

/**
 * @brief Get sspt_file list by region (remove sspt_file from sspt_proc list)
 *
 * @param proc Pointer on the sspt_proc struct
 * @param head[out] Pointer on the head list
 * @param start Region start
 * @param len Region length
 * @return Error code
 */
int sspt_proc_get_files_by_region(struct sspt_proc *proc,
				  struct list_head *head,
				  unsigned long start, size_t len)
{
	int ret = 0;
	struct sspt_file *file, *n;
	unsigned long end = start + len;

	list_for_each_entry_safe(file, n, &proc->file_head, list) {
		if (intersection(file->vm_start, file->vm_end, start, end)) {
			ret = 1;
			list_move(&file->list, head);
		}
	}

	return ret;
}

/**
 * @brief Insert sspt_file to sspt_proc list
 *
 * @param proc Pointer on the sspt_proc struct
 * @param head Pointer on the head list
 * @return Void
 */
void sspt_proc_insert_files(struct sspt_proc *proc, struct list_head *head)
{
	list_splice(head, &proc->file_head);
}

/**
 * @brief Add sspt_filter to sspt_proc list
 *
 * @param proc Pointer to sspt_proc struct
 * @param pfg Pointer to pf_group struct
 * @return Void
 */
void sspt_proc_add_filter(struct sspt_proc *proc, struct pf_group *pfg)
{
	struct sspt_filter *f;

	f = sspt_filter_create(proc, pfg);
	if (f)
		list_add(&f->list, &proc->filters.head);
}

/**
 * @brief Remove sspt_filter from sspt_proc list
 *
 * @param proc Pointer to sspt_proc struct
 * @param pfg Pointer to pf_group struct
 * @return Void
 */
void sspt_proc_del_filter(struct sspt_proc *proc, struct pf_group *pfg)
{
	struct sspt_filter *fl, *tmp;

	mutex_lock(&proc->filters.mtx);
	list_for_each_entry_safe(fl, tmp, &proc->filters.head, list) {
		if (fl->pfg == pfg) {
			list_del(&fl->list);
			sspt_filter_free(fl);
		}
	}
	mutex_unlock(&proc->filters.mtx);
}

/**
 * @brief Remove all sspt_filters from sspt_proc list
 *
 * @param proc Pointer to sspt_proc struct
 * @return Void
 */
void sspt_proc_del_all_filters(struct sspt_proc *proc)
{
	struct sspt_filter *fl, *tmp;

	mutex_lock(&proc->filters.mtx);
	list_for_each_entry_safe(fl, tmp, &proc->filters.head, list) {
		list_del(&fl->list);
		sspt_filter_free(fl);
	}
	mutex_unlock(&proc->filters.mtx);
}

/**
 * @brief Check if sspt_filter is already in sspt_proc list
 *
 * @param proc Pointer to sspt_proc struct
 * @param pfg Pointer to pf_group struct
 * @return Boolean
 */
bool sspt_proc_is_filter_new(struct sspt_proc *proc, struct pf_group *pfg)
{
	struct sspt_filter *fl;

	list_for_each_entry(fl, &proc->filters.head, list)
		if (fl->pfg == pfg)
			return false;

	return true;
}

void sspt_proc_on_each_filter(struct sspt_proc *proc,
			      void (*func)(struct sspt_filter *, void *),
			      void *data)
{
	struct sspt_filter *fl;

	list_for_each_entry(fl, &proc->filters.head, list)
		func(fl, data);
}

void sspt_proc_on_each_ip(struct sspt_proc *proc,
			  void (*func)(struct sspt_ip *, void *), void *data)
{
	struct sspt_file *file;

	list_for_each_entry(file, &proc->file_head, list)
		sspt_file_on_each_ip(file, func, data);
}

static void is_send_event(struct sspt_filter *f, void *data)
{
	bool *is_send = (bool *)data;

	if (!*is_send && f->pfg_is_inst)
		*is_send = !!pfg_msg_cb_get(f->pfg);
}

bool sspt_proc_is_send_event(struct sspt_proc *proc)
{
	bool is_send = false;

	/* FIXME: add read lock (deadlock in sampler) */
	sspt_proc_on_each_filter(proc, is_send_event, (void *)&is_send);

	return is_send;
}


static struct sspt_proc_cb *proc_cb;

int sspt_proc_cb_set(struct sspt_proc_cb *cb)
{
	if (cb && proc_cb)
		return -EBUSY;

	proc_cb = cb;

	return 0;
}
EXPORT_SYMBOL_GPL(sspt_proc_cb_set);

void sspt_proc_priv_create(struct sspt_proc *proc)
{
	if (proc_cb && proc_cb->priv_create)
		proc->private_data = proc_cb->priv_create(proc);
}

void sspt_proc_priv_destroy(struct sspt_proc *proc)
{
	if (proc->first_install && proc_cb && proc_cb->priv_destroy)
		proc_cb->priv_destroy(proc, proc->private_data);
}
