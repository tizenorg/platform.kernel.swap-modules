/*
 *  SWAP uprobe manager
 *  modules/us_manager/pf/pf_group.c
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


#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "proc_filters.h"
#include <us_manager/img/img_proc.h>
#include <us_manager/img/img_file.h>
#include <us_manager/img/img_ip.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/helper.h>
#include <writer/swap_writer_module.h>

struct pf_group {
	struct list_head list;
	struct img_proc *i_proc;
	struct proc_filter *filter;

	/* TODO: proc_list*/
	struct list_head proc_list;
};

struct pl_struct {
	struct list_head list;
	struct sspt_proc *proc;
};

static LIST_HEAD(pfg_list);

/* struct pl_struct */
static struct pl_struct *create_pl_struct(struct sspt_proc *proc)
{
	struct pl_struct *pls = kmalloc(sizeof(*pls), GFP_KERNEL);

	INIT_LIST_HEAD(&pls->list);
	pls->proc = proc;

	return pls;
}

static void free_pl_struct(struct pl_struct *pls)
{
	kfree(pls);
}

static void add_pl_struct(struct pf_group *pfg, struct pl_struct *pls)
{
	list_add(&pls->list, &pfg->proc_list);
}

static void del_pl_struct(struct pl_struct *pls)
{
	list_del(&pls->list);
}

void copy_proc_form_img_to_sspt(struct img_proc *i_proc, struct sspt_proc *proc)
{
	struct sspt_file *file;
	struct img_file *i_file;
	struct img_ip *i_ip;

	list_for_each_entry(i_file, &i_proc->file_list, list) {
		file = sspt_proc_find_file_or_new(proc, i_file->dentry);

		list_for_each_entry(i_ip, &i_file->ip_list, list)
			sspt_file_add_ip(file, i_ip->addr, i_ip->args);
	}
}

static struct pl_struct *find_pl_struct(struct pf_group *pfg,
					struct task_struct *task)
{
	struct pl_struct *pls;

	list_for_each_entry(pls, &pfg->proc_list, list) {
		if (pls->proc->tgid == task->tgid)
			return pls;
	}

	return NULL;
}

static struct sspt_proc *get_proc_by_pfg(struct pf_group *pfg,
					 struct task_struct *task)
{
	struct pl_struct *pls;

	pls = find_pl_struct(pfg, task);
	if (pls)
		return pls->proc;

	return NULL;
}

static struct sspt_proc *new_proc_by_pfg(struct pf_group *pfg,
					 struct task_struct *task)
{
	struct pl_struct *pls;
	struct sspt_proc *proc;

	proc = sspt_proc_get_by_task_or_new(task, pfg->filter->priv);
	copy_proc_form_img_to_sspt(pfg->i_proc, proc);

	pls = create_pl_struct(proc);
	add_pl_struct(pfg, pls);

	return proc;
}
/* struct pl_struct */

static struct pf_group *create_pfg(struct proc_filter *filter)
{
	struct pf_group *pfg = kmalloc(sizeof(*pfg), GFP_KERNEL);

	INIT_LIST_HEAD(&pfg->list);
	pfg->filter = filter;
	pfg->i_proc = create_img_proc();
	INIT_LIST_HEAD(&pfg->proc_list);

	return pfg;
}

static void free_pfg(struct pf_group *pfg)
{
	/* FIXME: */
	kfree(pfg);
}

static void add_pfg_by_list(struct pf_group *pfg)
{
	list_add(&pfg->list, &pfg_list);
}

static void del_pfg_by_list(struct pf_group *pfg)
{
	list_del(&pfg->list);
}

struct pf_group *get_pf_group_by_dentry(struct dentry *dentry, void *priv)
{
	struct pf_group *pfg;
	struct proc_filter *filter;

	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_dentry(pfg->filter, dentry))
			return pfg;
	}

	filter = create_pf_by_dentry(dentry, priv);
	pfg = create_pfg(filter);

	add_pfg_by_list(pfg);

	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_dentry);

struct pf_group *get_pf_group_by_tgid(pid_t tgid, void *priv)
{
	struct pf_group *pfg;
	struct proc_filter *filter;

	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_tgid(pfg->filter, tgid))
			return pfg;
	}

	filter = create_pf_by_tgid(tgid, priv);
	pfg = create_pfg(filter);

	add_pfg_by_list(pfg);

	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_tgid);

void put_pf_group(struct pf_group *pfg)
{

}

int pf_register_probe(struct pf_group *pfg, struct dentry *dentry,
		      unsigned long offset, const char *args)
{
	return img_proc_add_ip(pfg->i_proc, dentry, offset, args);
}
EXPORT_SYMBOL_GPL(pf_register_probe);

int pf_unregister_probe(struct pf_group *pfg, struct dentry *dentry,
			unsigned long offset)
{
	return img_proc_del_ip(pfg->i_proc, dentry, offset);
}
EXPORT_SYMBOL_GPL(pf_unregister_probe);

void call_page_fault(struct task_struct *task, unsigned long page_addr)
{
	struct pf_group *pfg, *pfg_first = NULL;
	struct sspt_proc *proc = NULL;

	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_task_f(pfg->filter, task) == NULL)
			continue;

		proc = get_proc_by_pfg(pfg, task);
		if (proc == NULL) {
			proc = new_proc_by_pfg(pfg, task);
			pfg_first = pfg;
		}
	}

	if (proc) {
		if (pfg_first) {
			struct dentry *dentry;

			dentry = get_dentry_by_pf(pfg_first->filter);
			if (dentry == NULL) {
				dentry = task->mm->exe_file ?
					 task->mm->exe_file->f_dentry :
					 NULL;
			}

			proc_info_msg(task, dentry);
			sspt_proc_install(proc);
		} else {
			sspt_proc_install_page(proc, page_addr);
		}
	}
}

void uninstall_proc(struct sspt_proc *proc)
{
	struct task_struct *task = proc->task;
	struct pf_group *pfg;
	struct pl_struct *pls;
	int i;

	list_for_each_entry(pfg, &pfg_list, list) {
		pls = find_pl_struct(pfg, task);
		if (pls) {
			del_pl_struct(pls);
			free_pl_struct(pls);
		}
	}

	task_lock(task);
	for (i = 0; task->mm == NULL; ++i) {
		task_unlock(task);
		if (i >= 10)
			BUG();

		schedule();
		task_lock(task);
	}

	sspt_proc_uninstall(proc, task, US_UNREGS_PROBE);
	task_unlock(task);

	sspt_proc_free(proc);
}

void call_mm_release(struct task_struct *task)
{
	struct sspt_proc *proc;

	proc = sspt_proc_get_by_task(task);
	if (proc)
		uninstall_proc(proc);
}

void uninstall_page(unsigned long addr)
{

}

void install_all(void)
{
	struct task_struct *task;
	int tmp_oops_in_progress;

	tmp_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
	rcu_read_lock();
	for_each_process(task) {
		if (task->tgid != task->pid)
			continue;

		if (is_kthread(task))
			continue;

		call_page_fault(task, 0xba00baab);
	}
	rcu_read_unlock();
	oops_in_progress = tmp_oops_in_progress;
}

static void clean_pfg(void)
{
	struct pf_group *pfg, *n;

	list_for_each_entry_safe(pfg, n, &pfg_list, list) {
		del_pfg_by_list(pfg);
		free_pfg(pfg);
	}
}

static void on_each_uninstall_proc(struct sspt_proc *proc, void *data)
{
	uninstall_proc(proc);
}

void uninstall_all(void)
{
	int tmp_oops_in_progress;

	tmp_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;

	on_each_proc(on_each_uninstall_proc, NULL);

	oops_in_progress = tmp_oops_in_progress;

	clean_pfg();
}

/* debug */
void pfg_print(struct pf_group *pfg)
{
	img_proc_print(pfg->i_proc);
}
EXPORT_SYMBOL_GPL(pfg_print);
/* debug */
