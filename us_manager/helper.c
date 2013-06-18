#include <dbi_kprobes.h>
#include <dbi_kprobes_deps.h>
#include <ksyms.h>
#include "us_proc_inst.h"
#include "us_slot_manager.h"
#include "storage.h"
#include "sspt/sspt.h"
#include "helper.h"

struct task_struct;

struct task_struct *check_task(struct task_struct *task);

/*
 ******************************************************************************
 *                               do_page_fault()                              *
 ******************************************************************************
 */

struct pf_data {
	unsigned long addr;
};

static int entry_handler_pf(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pf_data *data = (struct pf_data *)ri->data;

#if defined(CONFIG_X86)
	data->addr = read_cr2();
#elif defined(CONFIG_ARM)
	data->addr = regs->ARM_r0;
#else
#error this architecture is not supported
#endif

	return 0;
}

/* Detects when IPs are really loaded into phy mem and installs probes. */
static int ret_handler_pf(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task;
	unsigned long page_addr;

	task = current->group_leader;
	if (is_kthread(task))
		return 0;

	page_addr = ((struct pf_data *)ri->data)->addr & PAGE_MASK;
	call_page_fault(task, page_addr);

	return 0;
}

static struct kretprobe pf_kretprobe = {
	.entry_handler = entry_handler_pf,
	.handler = ret_handler_pf,
	.data_size = sizeof(struct pf_data)
};



/*
 ******************************************************************************
 *                              copy_process()                                *
 ******************************************************************************
 */

static void recover_child(struct task_struct *child_task, struct sspt_proc *proc)
{
	sspt_proc_uninstall(proc, child_task, US_DISARM);
	dbi_disarm_urp_inst_for_task(current, child_task);
}

static void rm_uprobes_child(struct task_struct *task)
{
	struct sspt_proc *proc = sspt_proc_get_by_task(current);
	if(proc) {
		recover_child(task, proc);
	}
}

/* Delete uprobs in children at fork */
static int ret_handler_cp(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = (struct task_struct *)regs_return_value(regs);

	if(!task || IS_ERR(task))
		goto out;

	if(task->mm != current->mm) {	/* check flags CLONE_VM */
		rm_uprobes_child(task);

		/*
		 * Ignoring page_addr, because it is
		 * first calling call_page_fault()
		 */
		call_page_fault(task, 0xbadc0de);
	}
out:
	return 0;
}

static struct kretprobe cp_kretprobe = {
	.handler = ret_handler_cp,
};



/*
 ******************************************************************************
 *                                mm_release()                                *
 ******************************************************************************
 */

/* Detects when target process removes IPs. */
static int mr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct sspt_proc *proc = NULL;
	struct task_struct *task;

#if defined(CONFIG_X86)
	task = (struct task_struct *)regs->EREG(ax);
#elif defined(CONFIG_ARM)
	task = (struct task_struct *)regs->ARM_r0;
#else
#error this architecture is not supported
#endif

	if (is_kthread(task))
		goto out;

	if (task->tgid != task->pid) {
		goto out;
	}

	call_mm_release(task);
out:
	return 0;
}

static struct kprobe mr_kprobe = {
	.pre_handler = mr_pre_handler
};



/*
 ******************************************************************************
 *                                 do_munmap()                                *
 ******************************************************************************
 */

static int remove_unmap_probes(struct task_struct *task, struct sspt_proc *proc, unsigned long start, size_t len)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;

	/* FIXME: not implemented */
	return 0;

	if ((start & ~PAGE_MASK) || start > TASK_SIZE || len > TASK_SIZE - start) {
		return -EINVAL;
	}

	if ((len = PAGE_ALIGN(len)) == 0) {
		return -EINVAL;
	}

	vma = find_vma(mm, start);
	if (vma && check_vma(vma)) {
		struct sspt_file *file;
		unsigned long end = start + len;
		struct dentry *dentry = vma->vm_file->f_dentry;

		file = sspt_proc_find_file(proc, dentry);
		if (file) {
			if (vma->vm_start == start || vma->vm_end == end) {
				sspt_file_uninstall(file, task, US_UNREGS_PROBE);
				file->loaded = 0;
			} else {
				unsigned long page_addr;
				struct sspt_page *page;

				for (page_addr = vma->vm_start; page_addr < vma->vm_end; page_addr += PAGE_SIZE) {
					page = sspt_find_page_mapped(file, page_addr);
					if (page) {
						sspt_unregister_page(page, US_UNREGS_PROBE, task);
					}
				}

				if (sspt_file_check_install_pages(file)) {
					file->loaded = 0;
				}
			}
		}
	}

	return 0;
}

/* Detects when target removes IPs. */
static int unmap_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	/* for ARM */
	struct mm_struct *mm;
	unsigned long start;
	size_t len;

#if defined(CONFIG_X86)
	mm = (struct mm_struct *)regs->EREG(ax);
	start = regs->EREG(dx);
	len = (size_t)regs->EREG(cx);
#elif defined(CONFIG_ARM)
	mm = (struct mm_struct *)regs->ARM_r0;
	start = regs->ARM_r1;
	len = (size_t)regs->ARM_r2;
#else
#error this architecture is not supported
#endif

	struct sspt_proc *proc = NULL;
	struct task_struct *task = current;

	if (is_kthread(task))
		goto out;

	proc = sspt_proc_get_by_task(task);
	if (proc) {
		if (remove_unmap_probes(task, proc, start, len)) {
			printk("ERROR do_munmap: start=%lx, len=%x\n", start, len);
		}
	}

out:
	return 0;
}

static struct kprobe unmap_kprobe = {
	.pre_handler = unmap_pre_handler
};



int register_helper(void)
{
	int ret = 0;

	/* install kprobe on 'do_munmap' to detect when for remove user space probes */
	ret = dbi_register_kprobe(&unmap_kprobe);
	if (ret) {
		printk("dbi_register_kprobe(do_munmap) result=%d!\n", ret);
		return ret;
	}

	/* install kprobe on 'mm_release' to detect when for remove user space probes */
	ret = dbi_register_kprobe(&mr_kprobe);
	if (ret != 0) {
		printk("dbi_register_kprobe(mm_release) result=%d!\n", ret);
		goto unregister_unmap;
	}


	/* install kretprobe on 'copy_process' */
	ret = dbi_register_kretprobe(&cp_kretprobe);
	if (ret) {
		printk("dbi_register_kretprobe(copy_process) result=%d!\n", ret);
		goto unregister_mr;
	}

	/* install kretprobe on 'do_page_fault' to detect when they will be loaded */
	ret = dbi_register_kretprobe(&pf_kretprobe);
	if (ret) {
		printk("dbi_register_kretprobe(do_page_fault) result=%d!\n", ret);
		goto unregister_cp;
	}

	return ret;

unregister_cp:
	dbi_unregister_kretprobe(&cp_kretprobe);

unregister_mr:
	dbi_unregister_kprobe(&mr_kprobe, NULL);

unregister_unmap:
	dbi_unregister_kprobe(&unmap_kprobe, NULL);

	return ret;
}

void unregister_helper(void)
{
	/* uninstall kretprobe with 'do_page_fault' */
	dbi_unregister_kretprobe(&pf_kretprobe);

	/* uninstall kretprobe with 'copy_process' */
	dbi_unregister_kretprobe(&cp_kretprobe);

	/* uninstall kprobe with 'mm_release' */
	dbi_unregister_kprobe(&mr_kprobe, NULL);

	/* uninstall kprobe with 'do_munmap' */
	dbi_unregister_kprobe(&unmap_kprobe, NULL);
}

int init_helper(void)
{
	unsigned long addr;
	addr = swap_ksyms("do_page_fault");
	if (addr == 0) {
		printk("Cannot find address for page fault function!\n");
		return -EINVAL;
	}
	pf_kretprobe.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("copy_process");
	if (addr == 0) {
		printk("Cannot find address for copy_process function!\n");
		return -EINVAL;
	}
	cp_kretprobe.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("mm_release");
	if (addr == 0) {
		printk("Cannot find address for mm_release function!\n");
		return -EINVAL;
	}
	mr_kprobe.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("do_munmap");
	if (addr == 0) {
		printk("Cannot find address for do_munmap function!\n");
		return -EINVAL;
	}
	unmap_kprobe.addr = (kprobe_opcode_t *)addr;

	return 0;
}

void uninit_helper(void)
{
}
