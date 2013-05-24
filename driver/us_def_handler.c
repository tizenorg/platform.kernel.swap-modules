#include <linux/module.h>
#include <asm/percpu.h>
#include <ec_probe.h>
#include <picl.h>
#include <swap_uprobes.h>
#include <sspt/ip.h>
#include <dbi_kprobes_deps.h>
#include "storage.h"
#include "us_proc_inst.h"

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
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;

#if defined(CONFIG_ARM)
	addr = ip->offset & 0x01 ? addr | 0x01 : addr;
#endif

	pack_event_info(US_PROBE_ID, RECORD_ENTRY, "ppppppp", addr, arg0, arg1,
			arg2, arg3, arg4, arg5);
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

		if (name)
			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppsp",
					addr, real_addr, name,
					real_addr - vma->vm_start);
		else
			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppp",
					addr, real_addr,
					real_addr - vma->vm_start);
	}
}

int uretprobe_event_handler(struct uretprobe_instance *probe,
			    struct pt_regs *regs,
			    struct us_ip *ip)
{
	int retval = regs_return_value(regs);
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;

	if (ip->got_addr && ip->flag_got == 0) {
		send_plt(ip);
		ip->flag_got = 1;
	}

#if defined(CONFIG_ARM)
	addr = ip->offset & 0x01 ? addr | 0x01 : addr;
#endif

	pack_event_info(US_PROBE_ID, RECORD_RET, "pd", addr, retval);

	return 0;
}
EXPORT_SYMBOL_GPL(uretprobe_event_handler);
