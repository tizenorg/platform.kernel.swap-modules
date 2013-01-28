#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/hash.h>
#include "storage.h"

#include "struct/ip.h"
#include "struct/page_probes.h"
#include "struct/file_probes.h"
#include "struct/proc_probes.h"

enum US_FLAGS {
	US_UNREGS_PROBE,
	US_NOT_RP2,
	US_DISARM
};







static void set_ip_kp_addr(struct us_ip *ip, struct page_probes *page_p, const struct sspt_file *file)
{
	unsigned long addr = file->vm_start + page_p->offset + ip->offset;
	ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
}

static void page_p_set_all_kp_addr(struct page_probes *page_p, const struct sspt_file *file)
{
	struct us_ip *ip;
	unsigned long addr;

	list_for_each_entry(ip, &page_p->ip_list, list) {
		addr = file->vm_start + page_p->offset + ip->offset;
		ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
//		printk("###       pp_set_all_kp_addr: start=%x, page_offset=%x, ip_offset=%x, addr=%x\n",
//				file_p->vm_start, page_p->offset, ip->offset, addr);
	}
}


#include "storage.h"

static void print_proc_probes(const struct sspt_procs *procs);

struct sspt_procs *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct sspt_procs *procs = proc_p_create(task_inst_info->m_f_dentry, 0);

	printk("####### get START #######\n");

	if (procs) {
		int i;

		printk("#2# get_file_probes: proc_p[dentry=%p]\n", procs->dentry);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			int k, j;
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct dentry *dentry = p_libs->m_f_dentry;
			const char *pach = p_libs->path;

			for (k = 0; k < p_libs->ips_count; ++k) {
				struct ip_data pd;
				us_proc_ip_t *ip = &p_libs->p_ips[k];
				unsigned long got_addr = 0;

				for (j = 0; j < p_libs->plt_count; ++j) {
					if (ip->offset == p_libs->p_plt[j].func_addr) {
						got_addr = p_libs->p_plt[j].got_addr;
						break;
					}
				}

				pd.flag_retprobe = 1;
				pd.offset = ip->offset;
				pd.got_addr = got_addr;
				pd.pre_handler = ip->jprobe.pre_entry;
				pd.jp_handler = ip->jprobe.entry;
				pd.rp_handler = ip->retprobe.handler;

				proc_p_add_dentry_probes(procs, pach, dentry, &pd, 1);
			}
		}
	}

	print_proc_probes(procs);

	printk("####### get  END  #######\n");

	return procs;
}

static int register_usprobe(struct task_struct *task, struct us_ip *ip, int atomic);
static int unregister_usprobe(struct task_struct *task, struct us_ip *ip, int atomic, int no_rp2);

static int register_usprobe_my(struct task_struct *task, struct us_ip *ip)
{
	return register_usprobe(task, ip, 1);
}

static int unregister_usprobe_my(struct task_struct *task, struct us_ip *ip, enum US_FLAGS flag)
{
	int err = 0;

	switch (flag) {
	case US_UNREGS_PROBE:
		err = unregister_usprobe(task, ip, 1, 0);
		break;
	case US_NOT_RP2:
		err = unregister_usprobe(task, ip, 1, 1);
		break;
	case US_DISARM:
		arch_disarm_uprobe(&ip->jprobe.kp, task);
		break;
	default:
		panic("incorrect value flag=%d", flag);
	}

	return err;
}

// debug
static void print_jprobe(struct jprobe *jp)
{
	printk("###         JP: entry=%x, pre_entry=%x\n",
			jp->entry, jp->pre_entry);
}

static void print_retprobe(struct kretprobe *rp)
{
	printk("###         RP: handler=%x\n",
			rp->handler);
}

static void print_page_probes(const struct page_probes *page_p)
{
	int i = 0;
	struct us_ip *ip;

	printk("###     offset=%x\n", page_p->offset);
	list_for_each_entry(ip, &page_p->ip_list, list) {

		printk("###       addr[%2d]=%x, J_addr=%x, R_addr=%x\n",
				i, ip->offset, ip->jprobe.kp.addr, ip->retprobe.kp.addr);
		print_jprobe(&ip->jprobe);
		print_retprobe(&ip->retprobe);
		++i;
	}
}

static const char *NA = "N/A";

static void print_file_probes(const struct sspt_file *file)
{
	int i, table_size;
	struct page_probes *page_p = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;

	if (file == NULL) {
		printk("### file_p == NULL\n");
		return;
	}

	table_size = (1 << file->page_probes_hash_bits);
	const char *name = (file->dentry) ? file->dentry->d_iname : NA;

	printk("### print_file_probes: path=%s, d_iname=%s, table_size=%d, vm_start=%x\n",
			file->path, name, table_size, file->vm_start);

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		hlist_for_each_entry_rcu(page_p, node, head, hlist) {
			print_page_probes(page_p);
		}
	}
}

static void print_proc_probes(const struct sspt_procs *procs)
{
	struct sspt_file *file;

	printk("### print_proc_probes\n");
	list_for_each_entry(file, &procs->file_list, list) {
		print_file_probes(file);
	}
	printk("### print_proc_probes\n");
}

void print_inst_us_proc(const inst_us_proc_t *task_inst_info)
{
	int i;
	int cnt = task_inst_info->libs_count;
	printk(  "### BUNDLE PRINT START ###\n");
	printk("\n### BUNDLE PRINT START ###\n");
	printk("### task_inst_info.libs_count=%d\n", cnt);

	for (i = 0; i < cnt; ++i) {
		int j;

		us_proc_lib_t *lib = &task_inst_info->p_libs[i];
		int cnt_j = lib->ips_count;
		char *path = lib->path;
		printk("###     path=%s, cnt_j=%d\n", path, cnt_j);

		for (j = 0; j < cnt_j; ++j) {
			struct us_ip *ips = &lib->p_ips[j];
			unsigned long offset = ips->offset;
			printk("###         offset=%x\n", offset);
		}
	}
	printk("### BUNDLE PRINT  END  ###\n");
}

#endif /* __NEW_DPF__ */
