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
#include "sspt_procs.h"
#include "sspt_debug.h"
#include "../us_proc_inst.h"
#include <swap_uprobes.h>


#include "../storage.h"
#include "../java_inst.h"

static void print_proc_probes(const struct sspt_procs *procs);

static inline struct sspt_procs *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct sspt_procs *procs = sspt_procs_create(task_inst_info->m_f_dentry, 0);

	printk("####### get START #######\n");

	if (procs) {
		int i;

		printk("#2# get_file_probes: proc_p[dentry=%p]\n", procs->dentry);

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
				pd.pre_handler = ip->jprobe.pre_entry;
				pd.jp_handler = (unsigned long) ip->jprobe.entry;
				pd.rp_handler = ip->retprobe.handler;

				sspt_procs_add_ip_data(procs, dentry, name, &pd);
			}
		}
	}

	add_java_inst(procs);

//	print_proc_probes(procs);

	printk("####### get  END  #######\n");

	return procs;
}


enum US_FLAGS {
	US_UNREGS_PROBE,
	US_NOT_RP2,
	US_DISARM
};

static inline int register_usprobe_my(struct task_struct *task, struct us_ip *ip)
{
	return register_usprobe(task, ip, 1);
}

static inline int unregister_usprobe_my(struct task_struct *task, struct us_ip *ip, enum US_FLAGS flag)
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
		disarm_uprobe(&ip->jprobe.kp, task);
		break;
	default:
		panic("incorrect value flag=%d", flag);
	}

	return err;
}

#endif /* __SSPT__ */
