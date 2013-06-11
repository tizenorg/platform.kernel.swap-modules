#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "proc_filters.h"
#include <img/img_proc.h>
#include <img/img_file.h>
#include <img/img_ip.h>
#include <sspt/sspt_proc.h>
#include <helper.h>

#include "../../driver/us_def_handler.h"

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

static LIST_HEAD(proc_list);

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
	/* FIXME: free */
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
	char *file_name;
	struct sspt_file *file;
	struct ip_data ip_d;
	struct dentry *dentry;

	struct img_file *i_file;
	struct img_ip *i_ip;

	list_for_each_entry(i_file, &i_proc->file_list, list) {
		dentry = i_file->dentry;
		file_name = dentry->d_iname;
		file = sspt_proc_find_file_or_new(proc, dentry, file_name);

		list_for_each_entry(i_ip, &i_file->ip_list, list) {
			ip_d.flag_retprobe = 1;
			ip_d.got_addr = 0;
			ip_d.jp_handler = ujprobe_event_handler;
			ip_d.offset = i_ip->addr;
			ip_d.pre_handler = ujprobe_event_pre_handler;
			ip_d.rp_handler = uretprobe_event_handler;

			sspt_file_add_ip(file, &ip_d);
		}
	}
}

static struct sspt_proc *get_proc_by_pfg(struct pf_group *pfg,
					 struct task_struct *task)
{
	struct pl_struct *pls;

	list_for_each_entry(pls, &pfg->proc_list, list) {
		if (pls->proc->tgid == task->tgid)
			return pls->proc;
	}

	return NULL;
}

static struct sspt_proc *get_proc_by_pfg_or_new(struct pf_group *pfg,
						struct task_struct *task)
{
	struct sspt_proc *proc;

	proc = get_proc_by_pfg(pfg, task);
	if (proc == NULL) {
		struct pl_struct *pls;

		/* or find?! */
		proc = sspt_proc_get_new(task);
		copy_proc_form_img_to_sspt(pfg->i_proc, proc);

		pls = create_pl_struct(proc);
		add_pl_struct(pfg, pls);
	}

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
	list_add(&pfg->list, &proc_list);
}

static void del_pfg_by_list(struct pf_group *pfg)
{
	list_del(&pfg->list);
}

struct pf_group *get_pf_group_by_dentry(struct dentry *dentry)
{
	struct pf_group *pfg;
	struct proc_filter *filter;

	list_for_each_entry(pfg, &proc_list, list) {
		if (check_pf_by_dentry(pfg->filter, dentry))
			return pfg;
	}

	filter = create_pf_by_dentry(dentry);
	pfg = create_pfg(filter);

	add_pfg_by_list(pfg);

	return pfg;
}
EXPORT_SYMBOL_GPL(get_pf_group_by_dentry);

struct pf_group *get_pf_group_by_tgid(pid_t tgid)
{
	struct pf_group *pfg;
	struct proc_filter *filter;

	list_for_each_entry(pfg, &proc_list, list) {
		if (check_pf_by_tgid(pfg->filter, tgid))
			return pfg;
	}

	filter = create_pf_by_tgid(tgid);
	pfg = create_pfg(filter);

	add_pfg_by_list(pfg);

	return pfg;
}

void put_pf_group(struct pf_group *pfg)
{

}

int pf_register_probe(struct pf_group *pfg, struct dentry *dentry,
		      unsigned long offset, void *pre_handler,
		      void *jp_handler, void *rp_handler)
{
	return img_proc_add_ip(pfg->i_proc, dentry, offset);
}
EXPORT_SYMBOL_GPL(pf_register_probe);

int pf_unregister_probe(struct pf_group *pfg, struct dentry *dentry,
			unsigned long offset)
{
	return img_proc_del_ip(pfg->i_proc, dentry, offset);
}

void install_all(void)
{

}

void uninstall_all(void)
{
//	struct pf_group *pfg;
//	list_for_each_entry(pfg, &proc_list, list) {
//		struct task_struct *task, ts;
//
//		rcu_read_lock();
//		for_each_process(task) {
//			if (task->tgid != task->pid)
//				continue;
//
//			if (is_kthread(task))
//				continue;
//
//			ts = check_task_f(pfg->filter, task);
//
//			if (ts) {
//				proc = sspt_proc_get_by_task_or_new(ts);
//				sspt_proc_install(proc);
//			}
//		}
//		rcu_read_unlock();
//	}
}


static void install_page_by_pfg(unsigned long addr, struct task_struct *task,
				struct pf_group *pfg)
{
	struct sspt_proc *proc;

	proc = get_proc_by_pfg(pfg, task);
	if (proc)
		goto install_proc;

	task = check_task_f(pfg->filter, task);
	if (task) {
		proc = get_proc_by_pfg_or_new(pfg, task);
		goto install_proc;
	}

	return;

install_proc:
	if (proc->first_install)
		sspt_proc_install_page(proc, addr & PAGE_MASK);
	else
		sspt_proc_install(proc);
}

void install_page(unsigned long addr)
{
	struct pf_group *pfg;
	struct task_struct *task, *ts;

	task = current->group_leader;
	if (is_kthread(task))
		return;

	list_for_each_entry(pfg, &proc_list, list) {
		install_page_by_pfg(addr, task, pfg);
	}
}

void uninstall_page(unsigned long addr)
{

}

/* debug */
void pfg_print(struct pf_group *pfg)
{
	img_proc_print(pfg->i_proc);
}
EXPORT_SYMBOL_GPL(pfg_print);
/* debug */
