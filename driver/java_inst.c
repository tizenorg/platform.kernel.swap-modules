/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/java_inst.c
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

#include "java_inst.h"

#ifdef __ANDROID

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "ec_probe.h"
#include "picl.h"
#include "storage.h"
#include "debug.h"
#include "sspt/ip.h"

struct dentry *libdvm_dentry = NULL;

struct dentry *dentry_by_path(const char *path);

unsigned long ujprobe_event_pre_handler(struct us_ip *ip, struct pt_regs *regs);
void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);

void add_java_inst(struct sspt_procs *procs)
{
	struct dentry *dentry = dentry_by_path("/system/lib/libdvm.so");
	libdvm_dentry = dentry;
	const char *name = "libdvm.so";

	struct ip_data ipd_entry =  {
		.offset = LIBDVM_ENTRY,
		.got_addr = 0,
		.pre_handler = ujprobe_event_pre_handler,
		.jp_handler = ujprobe_event_handler,
		.rp_handler = 0,
		.flag_retprobe = 0
	};

	sspt_procs_add_ip_data(procs, dentry, name, &ipd_entry);


	struct ip_data ipd_return =  {
		.offset = LIBDVM_RETURN,
		.got_addr = 0,
		.pre_handler = ujprobe_event_pre_handler,
		.jp_handler = ujprobe_event_handler,
		.rp_handler = 0,
		.flag_retprobe = 0
	};

	sspt_procs_add_ip_data(procs, dentry, name, &ipd_return);
}

static inline int pre_handle_java_event(unsigned long start, unsigned long addr, struct pt_regs *regs)
{
	if (addr == start + LIBDVM_ENTRY) {
		unsigned long *p_met = (unsigned long *)regs->ARM_r0;
		char *met_name = p_met ? (char *)(p_met[4]) : 0;
		unsigned long *p_cl = p_met ? (unsigned long *)p_met[0] : 0;
		char *cl_name = p_cl ? (char *)(p_cl[6]) : 0;

		if (!cl_name || !met_name) {
			EPRINTF("warn: class name or method name null\n");
		} else {
			pack_event_info(JAVA_PROBE_ID, RECORD_ENTRY, "pss", addr, cl_name, met_name);
		}

		dbi_uprobe_return ();

		return 1;
	} else if (addr == start + LIBDVM_RETURN) {
		unsigned long *p_th = (unsigned long *)regs->ARM_r6;
		unsigned long *p_st = p_th;
		unsigned long *p_met = p_st ? (unsigned long *)p_st[2] : 0;
		char *met_name = p_met ? (char *)(p_met[4]) : 0;
		unsigned long *p_cl = p_met ? (unsigned long *)p_met[0] : 0;
		char *cl_name = p_cl ? (char *)(p_cl[6]) : 0;

		if (!cl_name || !met_name) {
			EPRINTF("warn: class name or method name null\n");
		} else {
			pack_event_info(JAVA_PROBE_ID, RECORD_RET, "pss", addr, cl_name, met_name);
		}

		dbi_uprobe_return ();

		return 1;
	}

	return 0;
}

int handle_java_event(struct pt_regs *regs)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr = regs->ARM_pc;

	if (mm && libdvm_dentry) {
		struct vm_area_struct *vma = find_vma(mm, addr);
		if (vma && (vma->vm_flags & VM_EXEC) &&
		    vma->vm_file && vma->vm_file->f_dentry &&
		    (vma->vm_file->f_dentry == libdvm_dentry)) {
			return pre_handle_java_event(vma->vm_start, addr, regs);
		}
	}

	return 0;
}

#endif /* __ANDROID */
