/*
 *  SWAP uprobe manager
 *  modules/us_manager/us_def_handler.c
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
#include <asm/percpu.h>
#include <swap_uprobes.h>
#include <sspt/ip.h>
#include <dbi_kprobes_deps.h>
#include <sspt/sspt.h>
#include <writer/swap_writer_module.h>

DEFINE_PER_CPU(struct us_ip *, gpCurIp) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpCurIp);
DEFINE_PER_CPU(struct pt_regs *, gpUserRegs) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpUserRegs);

unsigned long ujprobe_event_pre_handler(struct us_ip *ip, struct pt_regs *regs)
{
	__get_cpu_var(gpCurIp) = ip;
	__get_cpu_var(gpUserRegs) = regs;

	return 0;
}
EXPORT_SYMBOL_GPL(ujprobe_event_pre_handler);

void ujprobe_event_handler(unsigned long arg0, unsigned long arg1,
			   unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5)
{
	struct us_ip *ip = __get_cpu_var(gpCurIp);
	struct us_ip *regs = __get_cpu_var(gpUserRegs);
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;

#if defined(CONFIG_ARM)
	addr = ip->offset & 0x01 ? addr | 0x01 : addr;
#endif

	entry_event(ip->jprobe.args, regs, PT_US, PST_NONE);

	swap_ujprobe_return();
}
EXPORT_SYMBOL_GPL(ujprobe_event_handler);

static void send_plt(struct us_ip *ip)
{
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;
	struct vm_area_struct *vma = find_vma(current->mm, addr);

	if (vma && check_vma(vma)) {
		char *name = NULL;
		unsigned long real_addr;
		unsigned long real_got = current->mm->exe_file == vma->vm_file ?
					 ip->got_addr :
					 ip->got_addr + vma->vm_start;

		if (!read_proc_vm_atomic(current, real_got, &real_addr, sizeof(real_addr))) {
			printk("Failed to read got %lx at memory address %lx!\n", ip->got_addr, real_got);
			return;
		}

		vma = find_vma(current->mm, real_addr);
		if (vma && (vma->vm_start <= real_addr) && (vma->vm_end > real_addr)) {
			name = vma->vm_file ? vma->vm_file->f_dentry->d_iname : NULL;
		} else {
			printk("Failed to get vma, includes %lx address\n", real_addr);
			return;
		}

//		if (name)
//			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppsp",
//					addr, real_addr, name,
//					real_addr - vma->vm_start);
//		else
//			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppp",
//					addr, real_addr,
//					real_addr - vma->vm_start);
	}
}

int uretprobe_event_handler(struct uretprobe_instance *probe,
			    struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct us_ip *ip = container_of(probe->rp, struct us_ip, retprobe);
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;

	if (ip->got_addr && ip->flag_got == 0) {
		send_plt(ip);
		ip->flag_got = 1;
	}

#if defined(CONFIG_ARM)
	addr = ip->offset & 0x01 ? addr | 0x01 : addr;
#endif

	exit_event(regs, addr);

	return 0;
}
EXPORT_SYMBOL_GPL(uretprobe_event_handler);
