#ifndef __SSPT__
#define __SSPT__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt.h
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

#include "ip.h"
#include "sspt_page.h"
#include "sspt_file.h"
#include "sspt_proc.h"
#include "sspt_debug.h"
#include <swap_uprobes.h>
#include "us_def_handler.h"


#include "../../driver/storage.h"

#include "picl.h"
#include "../../common/ec_probe.h"

#include <us_manager.h>
#include <pf/pf_group.h>

static void print_proc_probes(const struct sspt_proc *proc);

struct sspt_proc;

static inline struct sspt_proc *get_file_probes(inst_us_proc_t *task_inst_info)
{
	int i, ret;
	struct pf_group *pfg;

	pfg = get_pf_group_by_dentry(task_inst_info->m_f_dentry);

	for (i = 0; i < task_inst_info->libs_count; ++i) {
		int k, j;
		us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
		struct dentry *dentry = p_libs->m_f_dentry;
		char *path = p_libs->path;
		char *name = strrchr(path, '/');
		name = name ? name + 1 : path;

		for (k = 0; k < p_libs->ips_count; ++k) {
			us_proc_ip_t *ip = &p_libs->p_ips[k];
			unsigned long got_addr = 0;

			for (j = 0; j < p_libs->plt_count; ++j) {
				if (ip->offset == p_libs->p_plt[j].func_addr) {
					got_addr = p_libs->p_plt[j].got_addr;
					break;
				}
			}

			ret = pf_register_probe(pfg, dentry, ip->offset, "dddd");
			if (ret)
				printk("### ERROR: pf_register_probe ret=%d\n", ret);
		}
	}

	printk("####### get  END  #######\n");

	pfg_print(pfg);

	return NULL;
}

static int check_vma(struct vm_area_struct *vma)
{
	return vma->vm_file && !(vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_ACCOUNT) ||
			!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) ||
			!(vma->vm_flags & (VM_READ | VM_MAYREAD)));
}

static inline int sspt_register_usprobe(struct us_ip *ip)
{
	int ret = 0;

	/* for juprobe */
	ip->jprobe.priv_arg = ip;
	ip->jprobe.up.task = ip->page->file->proc->task;
	ip->jprobe.up.sm = ip->page->file->proc->sm;

	/* for retuprobe */
	ip->retprobe.priv_arg = ip;
	ip->retprobe.up.task = ip->page->file->proc->task;
	ip->retprobe.up.sm = ip->page->file->proc->sm;

	ret = dbi_register_ujprobe(&ip->jprobe);
	if (ret) {
		if (ret == -ENOEXEC) {
			pack_event_info(ERR_MSG_ID, RECORD_ENTRY, "dp",
					0x1, ip->jprobe.up.kp.addr);
		}
		printk("dbi_register_ujprobe() failure %d\n", ret);
		return ret;
	}

	if (ip->flag_retprobe) {
		ret = dbi_register_uretprobe(&ip->retprobe);
		if (ret) {
			struct sspt_file *file = ip->page->file;
			char *name = file->dentry->d_iname;
			unsigned long addr =ip->retprobe.up.kp.addr;
			unsigned long offset = addr - file->vm_start;

			printk("dbi_register_uretprobe() failure %d (%s:%x|%x)\n",
			       ret, name, offset, ip->retprobe.up.kp.opcode);

			return ret;
		}
	}

	return 0;
}

static inline int do_unregister_usprobe(struct us_ip *ip)
{
	dbi_unregister_ujprobe(&ip->jprobe);

	if (ip->flag_retprobe) {
		dbi_unregister_uretprobe(&ip->retprobe);
	}

	return 0;
}

static inline int sspt_unregister_usprobe(struct task_struct *task, struct us_ip *ip, enum US_FLAGS flag)
{
	int err = 0;

	switch (flag) {
	case US_UNREGS_PROBE:
		err = do_unregister_usprobe(ip);
		break;
	case US_DISARM:
		disarm_uprobe(&ip->jprobe.up.kp, task);
		break;
	default:
		panic("incorrect value flag=%d", flag);
	}

	return err;
}

#endif /* __SSPT__ */
