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
#include "../us_proc_inst.h"
#include <swap_uprobes.h>
#include "us_def_handler.h"


#include "../storage.h"

static void print_proc_probes(const struct sspt_proc *proc);

static inline struct sspt_proc *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct sspt_proc *proc = sspt_proc_create(task_inst_info->m_f_dentry, 0);

	printk("####### get START #######\n");

	if (proc) {
		int i;

		printk("#2# get_file_probes: proc_p[dentry=%p]\n", proc->dentry);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			int k, j;
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct dentry *dentry = p_libs->m_f_dentry;
			char *path = p_libs->path;
			char *name = strrchr(path, '/');
			name = name ? name + 1 : path;

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
				pd.pre_handler = ip->jprobe.pre_entry ? ip->jprobe.pre_entry : ujprobe_event_pre_handler;
				pd.jp_handler = (unsigned long) (ip->jprobe.entry ? ip->jprobe.entry : ujprobe_event_handler);
				pd.rp_handler = ip->retprobe.handler ?  ip->retprobe.handler : uretprobe_event_handler;

				sspt_proc_add_ip_data(proc, dentry, name, &pd);
			}
		}
	}

//	print_proc_probes(proc);

	printk("####### get  END  #######\n");

	return proc;
}


enum US_FLAGS {
	US_UNREGS_PROBE,
	US_DISARM
};

static inline int sspt_register_usprobe(struct us_ip *ip)
{
	int ret = 0;

	ip->jprobe.priv_arg = ip;
	ip->jprobe.up.task = ip->page->file->proc->task;
	ip->jprobe.up.sm = ip->page->file->proc->sm;
	ret = dbi_register_ujprobe(&ip->jprobe);
	if (ret) {
		if (ret == -ENOEXEC) {
			pack_event_info(ERR_MSG_ID, RECORD_ENTRY, "dp",
					0x1,
					ip->jprobe.up.kp.addr);
		}
		printk("dbi_register_ujprobe() failure %d\n", ret);
		return ret;
	}

	if (ip->flag_retprobe) {
		ip->retprobe.priv_arg = ip;
		ip->retprobe.up.task = ip->page->file->proc->task;
		ip->retprobe.up.sm = ip->page->file->proc->sm;
		ret = dbi_register_uretprobe(&ip->retprobe);
		if (ret) {
			printk("dbi_register_uretprobe() failure %d\n", ret);
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
