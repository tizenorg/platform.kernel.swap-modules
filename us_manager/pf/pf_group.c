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
#include <linux/namei.h>

#include "pf_group.h"
#include "proc_filters.h"
#include "../sspt/sspt_filter.h"
#include <us_manager/img/img_proc.h>
#include <us_manager/img/img_file.h>
#include <us_manager/img/img_ip.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/helper.h>

struct pf_group {
	struct list_head list;
	struct img_proc *i_proc;
	struct proc_filter filter;
	struct pfg_msg_cb *msg_cb;
	atomic_t usage;

	/* TODO: proc_list*/
	struct list_head proc_list;
};

struct pl_struct {
	struct list_head list;
	struct sspt_proc *proc;
};

static LIST_HEAD(pfg_list);
static DEFINE_RWLOCK(pfg_list_lock);

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
/* struct pl_struct */

static struct pf_group *create_pfg(void)
{
	struct pf_group *pfg = kmalloc(sizeof(*pfg), GFP_KERNEL);

	if (pfg == NULL)
		return NULL;

	pfg->i_proc = create_img_proc();
	if (pfg->i_proc == NULL)
		goto create_pfg_fail;

	INIT_LIST_HEAD(&pfg->list);
	memset(&pfg->filter, 0, sizeof(pfg->filter));
	INIT_LIST_HEAD(&pfg->proc_list);
	pfg->msg_cb = NULL;
	atomic_set(&pfg->usage, 1);

	return pfg;

create_pfg_fail:

	kfree(pfg);

	return NULL;
}

static void free_pfg(struct pf_group *pfg)
{
	struct pl_struct *pl;

	free_img_proc(pfg->i_proc);
	free_pf(&pfg->filter);
	list_for_each_entry(pl, &pfg->proc_list, list)
		sspt_proc_del_filter(pl->proc, pfg);
	kfree(pfg);
}

/* called with pfg_list_lock held */
static void add_pfg_by_list(struct pf_group *pfg)
{
	list_add(&pfg->list, &pfg_list);
}

/* called with pfg_list_lock held */
static void del_pfg_by_list(struct pf_group *pfg)
{
	list_del(&pfg->list);
}


static void msg_info(struct sspt_filter *f, void *data)
{
	if (f->pfg_is_inst == false) {
		struct pfg_msg_cb *cb;

		f->pfg_is_inst = true;

		cb = pfg_msg_cb_get(f->pfg);
		if (cb) {
			struct dentry *dentry;

			dentry = (struct dentry *)f->pfg->filter.priv;

			if (cb->msg_info)
				cb->msg_info(f->proc->task, dentry);

			if (cb->msg_status_info)
				cb->msg_status_info(f->proc->task);
		}
	}
}

static void first_install(struct task_struct *task, struct sspt_proc *proc)
{
	down_write(&task->mm->mmap_sem);
	sspt_proc_on_each_filter(proc, msg_info, NULL);
	sspt_proc_install(proc);
	up_write(&task->mm->mmap_sem);
}

static void subsequent_install(struct task_struct *task,
			       struct sspt_proc *proc, unsigned long page_addr)
{
	down_write(&task->mm->mmap_sem);
	sspt_proc_install_page(proc, page_addr);
	up_write(&task->mm->mmap_sem);
}

/**
 * @brief Get dentry struct by path
 *
 * @param path Path to file
 * @return Pointer on dentry struct on NULL
 */
struct dentry *dentry_by_path(const char *path)
{
	struct dentry *dentry;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	struct path st_path;
	if (kern_path(path, LOOKUP_FOLLOW, &st_path) != 0) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	struct nameidata nd;
	if (path_lookup(path, LOOKUP_FOLLOW, &nd) != 0) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
		printk("failed to lookup dentry for path %s!\n", path);
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	dentry = nd.dentry;
	path_release(&nd);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
	dentry = nd.path.dentry;
	path_put(&nd.path);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	dentry = st_path.dentry;
	path_put(&st_path);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25) */
	return dentry;
}
EXPORT_SYMBOL_GPL(dentry_by_path);


int pfg_msg_cb_set(struct pf_group *pfg, struct pfg_msg_cb *msg_cb)
{
	if (pfg->msg_cb)
		return -EBUSY;

	pfg->msg_cb = msg_cb;

	return 0;
}
EXPORT_SYMBOL_GPL(pfg_msg_cb_set);

void pfg_msg_cb_reset(struct pf_group *pfg)
{
	pfg->msg_cb = NULL;
}
EXPORT_SYMBOL_GPL(pfg_msg_cb_reset);

struct pfg_msg_cb *pfg_msg_cb_get(struct pf_group *pfg)
{
	return pfg->msg_cb;
}

/**
 * @brief Get pf_group struct by dentry
 *
 * @param dentry Dentry of file
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_by_dentry(struct dentry *dentry, void *priv)
{
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_dentry(&pfg->filter, dentry)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = create_pfg();
	if (pfg == NULL)
		goto unlock;

	set_pf_by_dentry(&pfg->filter, dentry, priv);

	add_pfg_by_list(pfg);

unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_dentry);

/**
 * @brief Get pf_group struct by TGID
 *
 * @param tgid Thread group ID
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_by_tgid(pid_t tgid, void *priv)
{
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_tgid(&pfg->filter, tgid)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = create_pfg();
	if (pfg == NULL)
		goto unlock;

	set_pf_by_tgid(&pfg->filter, tgid, priv);

	add_pfg_by_list(pfg);

unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_tgid);

/**
 * @brief Get pf_group struct by comm
 *
 * @param comm Task comm
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_by_comm(char *comm, void *priv)
{
	int ret;
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_by_comm(&pfg->filter, comm)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = create_pfg();
	if (pfg == NULL)
		goto unlock;

	ret = set_pf_by_comm(&pfg->filter, comm, priv);
	if (ret) {
		printk(KERN_ERR "ERROR: set_pf_by_comm, ret=%d\n", ret);
		free_pfg(pfg);
		pfg = NULL;
		goto unlock;
	}

	add_pfg_by_list(pfg);
unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_comm);

/**
 * @brief Get pf_group struct for each process
 *
 * @param priv Private data
 * @return Pointer on pf_group struct
 */
struct pf_group *get_pf_group_dumb(void *priv)
{
	struct pf_group *pfg;

	write_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_pf_dumb(&pfg->filter)) {
			atomic_inc(&pfg->usage);
			goto unlock;
		}
	}

	pfg = create_pfg();
	if (pfg == NULL)
		goto unlock;

	set_pf_dumb(&pfg->filter, priv);

	add_pfg_by_list(pfg);

unlock:
	write_unlock(&pfg_list_lock);
	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_dumb);

/**
 * @brief Put pf_group struct
 *
 * @param pfg Pointer to the pf_group struct
 * @return Void
 */
void put_pf_group(struct pf_group *pfg)
{
	if (atomic_dec_and_test(&pfg->usage)) {
		write_lock(&pfg_list_lock);
		del_pfg_by_list(pfg);
		write_unlock(&pfg_list_lock);

		free_pfg(pfg);
	}
}
EXPORT_SYMBOL_GPL(put_pf_group);

/**
 * @brief Register prober for pf_grpup struct
 *
 * @param pfg Pointer to the pf_group struct
 * @param dentry Dentry of file
 * @param offset Function offset
 * @param probe_info Pointer to the related probe_info struct
 * @return Error code
 */
int pf_register_probe(struct pf_group *pfg, struct dentry *dentry,
		      unsigned long offset, struct probe_info *probe_i)
{
	return img_proc_add_ip(pfg->i_proc, dentry, offset, probe_i);
}
EXPORT_SYMBOL_GPL(pf_register_probe);

/**
 * @brief Unregister prober from pf_grpup struct
 *
 * @param pfg Pointer to the pf_group struct
 * @param dentry Dentry of file
 * @param offset Function offset
 * @return Error code
 */
int pf_unregister_probe(struct pf_group *pfg, struct dentry *dentry,
			unsigned long offset)
{
	return img_proc_del_ip(pfg->i_proc, dentry, offset);
}
EXPORT_SYMBOL_GPL(pf_unregister_probe);

/**
 * @brief Check the task, to meet the filter criteria
 *
 * @prarm task Pointer on the task_struct struct
 * @return
 *       - 0 - false
 *       - 1 - true
 */
int check_task_on_filters(struct task_struct *task)
{
	int ret = 0;
	struct pf_group *pfg;

	read_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_task_f(&pfg->filter, task)) {
			ret = 1;
			goto unlock;
		}
	}

unlock:
	read_unlock(&pfg_list_lock);
	return ret;
}

static int pfg_add_proc(struct pf_group *pfg, struct sspt_proc *proc)
{
	struct pl_struct *pls;

	pls = create_pl_struct(proc);
	if (pls == NULL)
		return -ENOMEM;

	add_pl_struct(pfg, pls);

	return 0;
}

enum pf_inst_flag {
	PIF_NONE,
	PIF_FIRST,
	PIF_SECOND,
	PIF_ADD_PFG
};

static enum pf_inst_flag pfg_check_task(struct task_struct *task)
{
	struct pf_group *pfg;
	struct sspt_proc *proc = NULL;
	enum pf_inst_flag flag = PIF_NONE;

	read_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		if (check_task_f(&pfg->filter, task) == NULL)
			continue;

		if (proc == NULL)
			proc = sspt_proc_get_by_task(task);

		if (proc) {
			flag = flag == PIF_NONE ? PIF_SECOND : flag;
		} else if (task->tgid == task->pid) {
			proc = sspt_proc_get_by_task_or_new(task);
			if (proc == NULL) {
				printk(KERN_ERR "cannot create sspt_proc\n");
				break;
			}
			flag = PIF_FIRST;
		}

		if (proc && sspt_proc_is_filter_new(proc, pfg)) {
			img_proc_copy_to_sspt(pfg->i_proc, proc);
			sspt_proc_add_filter(proc, pfg);
			pfg_add_proc(pfg, proc);
			flag = flag == PIF_FIRST ? flag : PIF_ADD_PFG;
		}
	}
	read_unlock(&pfg_list_lock);

	return flag;
}

/**
 * @brief Check task and install probes on demand
 *
 * @prarm task Pointer on the task_struct struct
 * @return Void
 */
void check_task_and_install(struct task_struct *task)
{
	struct sspt_proc *proc;
	enum pf_inst_flag flag;

	flag = pfg_check_task(task);
	switch (flag) {
	case PIF_FIRST:
	case PIF_ADD_PFG:
		proc = sspt_proc_get_by_task(task);
		first_install(task, proc);
		break;

	case PIF_NONE:
	case PIF_SECOND:
		break;
	}
}

/**
 * @brief Check task and install probes on demand
 *
 * @prarm task Pointer on the task_struct struct
 * @param page_addr Page fault address
 * @return Void
 */
void call_page_fault(struct task_struct *task, unsigned long page_addr)
{
	struct sspt_proc *proc;
	enum pf_inst_flag flag;

	flag = pfg_check_task(task);
	switch (flag) {
	case PIF_FIRST:
	case PIF_ADD_PFG:
		proc = sspt_proc_get_by_task(task);
		first_install(task, proc);
		break;

	case PIF_SECOND:
		proc = sspt_proc_get_by_task(task);
		subsequent_install(task, proc, page_addr);
		break;

	case PIF_NONE:
		break;
	}
}

/**
 * @brief Uninstall probes from the sspt_proc struct
 *
 * @prarm proc Pointer on the sspt_proc struct
 * @return Void
 */

/* called with sspt_proc_write_lock() */
void uninstall_proc(struct sspt_proc *proc)
{
	struct task_struct *task = proc->task;
	struct pf_group *pfg;
	struct pl_struct *pls;

	read_lock(&pfg_list_lock);
	list_for_each_entry(pfg, &pfg_list, list) {
		pls = find_pl_struct(pfg, task);
		if (pls) {
			del_pl_struct(pls);
			free_pl_struct(pls);
		}
	}
	read_unlock(&pfg_list_lock);

	task_lock(task);
	BUG_ON(task->mm == NULL);
	sspt_proc_uninstall(proc, task, US_UNREGS_PROBE);
	task_unlock(task);

	sspt_proc_del_all_filters(proc);
	sspt_proc_free(proc);
}

/**
 * @brief Remove probes from the task on demand
 *
 * @prarm task Pointer on the task_struct struct
 * @return Void
 */
void call_mm_release(struct task_struct *task)
{
	struct sspt_proc *proc;

	sspt_proc_write_lock();

	proc = sspt_proc_get_by_task(task);
	if (proc)
		/* TODO: uninstall_proc - is not atomic context */
		uninstall_proc(proc);

	sspt_proc_write_unlock();
}

/**
 * @brief Legacy code, it is need remove
 *
 * @param addr Page address
 * @return Void
 */
void uninstall_page(unsigned long addr)
{

}

/**
 * @brief Install probes on running processes
 *
 * @return Void
 */
void install_all(void)
{
#if !defined(CONFIG_ARM)
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

		check_task_and_install(task);
	}
	rcu_read_unlock();
	oops_in_progress = tmp_oops_in_progress;
#endif /* CONFIG_ARM */
}

static void on_each_uninstall_proc(struct sspt_proc *proc, void *data)
{
	uninstall_proc(proc);
}

/**
 * @brief Uninstall probes from all processes
 *
 * @return Void
 */
void uninstall_all(void)
{
	sspt_proc_write_lock();
	on_each_proc_no_lock(on_each_uninstall_proc, NULL);
	sspt_proc_write_unlock();
}

/**
 * @brief For debug
 *
 * @param pfg Pointer to the pf_group struct
 * @return Void
 */

/* debug */
void pfg_print(struct pf_group *pfg)
{
	img_proc_print(pfg->i_proc);
}
EXPORT_SYMBOL_GPL(pfg_print);
/* debug */
