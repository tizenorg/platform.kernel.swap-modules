#include <linux/module.h>
#include <sspt/sspt.h>
#include <sspt/sspt_proc.h>
#include <sspt/sspt_page.h>
#include <helper.h>
#include "pf/proc_filters.h"

#include <writer/swap_writer_module.h>

struct proc_filter *pf;

void (*ptr_pack_task_event_info)(struct task_struct *task,
				 int probe_id,
				 int record_type,
				 const char *fmt, ...) = NULL;

EXPORT_SYMBOL_GPL(ptr_pack_task_event_info);

struct task_struct *check_task(struct task_struct *task)
{
	if (is_kthread(task))
		return NULL;

	return pf->call(pf, task);
}

int usm_register_probe(struct dentry *dentry, unsigned long offset,
		       void *pre_handler, void *jp_handler, void *rp_handler)
{
/*
	char *file_name;
	struct sspt_file *file;
	struct ip_data ip_d;

	file_name = dentry->d_iname;
	file = sspt_proc_find_file_or_new(proc_base, dentry, file_name);

	ip_d.flag_retprobe = 1;
	ip_d.got_addr = 0;
	ip_d.jp_handler = jp_handler;
	ip_d.offset = offset;
	ip_d.pre_handler = pre_handler;
	ip_d.rp_handler = rp_handler;

	sspt_file_add_ip(file, &ip_d);
*/

	return 0;
}
EXPORT_SYMBOL_GPL(usm_register_probe);

int usm_unregister_probe(struct dentry *dentry, unsigned long offset)
{
/*
	struct sspt_file *file;
	struct sspt_page *page;
	struct us_ip *ip;

	file = sspt_proc_find_file(proc_base, dentry);
	if (file == NULL)
		return -EINVAL;

	page = sspt_get_page(file, offset);
	if (page == NULL)
		return -EINVAL;

	ip = sspt_find_ip(page, offset & ~PAGE_MASK);
	if (ip == NULL) {
		sspt_put_page(page);
		return -EINVAL;
	}

	sspt_del_ip(ip);
	sspt_put_page(page);
*/

	return 0;
}
EXPORT_SYMBOL_GPL(usm_unregister_probe);

int usm_stop(void)
{
	int iRet = 0, found = 0;
	struct task_struct *task = NULL;
	struct sspt_proc *proc;
	int tmp_oops_in_progress;

	unregister_helper();

	if (iRet)
		printk("uninstall_kernel_probe(do_munmap) result=%d!\n", iRet);

	uninstall_all();

/*
	tmp_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
	rcu_read_lock();
	for_each_process(task) {
		if (is_kthread(task))
			continue;

		proc = sspt_proc_get_by_task(task);
		if (proc) {
			int ret = sspt_proc_uninstall(proc, task, US_UNREGS_PROBE);
			if (ret)
				printk("failed to uninstall IPs (%d)!\n", ret);

			dbi_unregister_all_uprobes(task);
		}
	}
	rcu_read_unlock();
	oops_in_progress = tmp_oops_in_progress;

	free_pf(pf);
*/

	sspt_proc_free_all();

	return iRet;
}
EXPORT_SYMBOL_GPL(usm_stop);

int usm_start(void)
{
	int ret, i;
	struct task_struct *task = NULL, *ts;
	struct sspt_proc *proc;
	int tmp_oops_in_progress;

	ret = register_helper();
	if (ret) {
		return ret;
	}

	install_all();

/*
	tmp_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
	rcu_read_lock();
	for_each_process(task) {
		if (is_kthread(task))
			continue;

		ts = check_task(task);

		if (ts) {
			proc = sspt_proc_get_by_task_or_new(ts);
			sspt_proc_install(proc);
		}
	}
	rcu_read_unlock();
	oops_in_progress = tmp_oops_in_progress;
*/
	return 0;
}
EXPORT_SYMBOL_GPL(usm_start);

static int __init init_us_manager(void)
{
	int ret;

	init_msg(32*1024);

	ret = init_helper();
	if (ret)
		return ret;

	return 0;
}

static void __exit exit_us_manager(void)
{
	uninit_msg();
	uninit_helper();
}

module_init(init_us_manager);
module_exit(exit_us_manager);

MODULE_LICENSE ("GPL");

