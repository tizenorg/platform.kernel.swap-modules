/*
 *  SWAP uprobe manager
 *  modules/us_manager/helper.c
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


#include <kprobe/dbi_kprobes.h>
#include <kprobe/dbi_kprobes_deps.h>
#include <ksyms/ksyms.h>
#include <writer/kernel_operations.h>
#include <writer/swap_writer_module.h>
#include "us_slot_manager.h"
#include "sspt/sspt.h"
#include "helper.h"

struct task_struct;

struct task_struct *check_task(struct task_struct *task);

static atomic_t stop_flag = ATOMIC_INIT(0);


/*
 ******************************************************************************
 *                               do_page_fault()                              *
 ******************************************************************************
 */

struct pf_data {
	unsigned long addr;
};

static int entry_handler_mf(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pf_data *data = (struct pf_data *)ri->data;

	data->addr = swap_get_karg(regs, 2);

	return 0;
}

/* Detects when IPs are really loaded into phy mem and installs probes. */
static int ret_handler_mf(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = current;
	unsigned long page_addr;

	if (is_kthread(task))
		return 0;

	/* TODO: check return value */
	page_addr = ((struct pf_data *)ri->data)->addr & PAGE_MASK;
	call_page_fault(task, page_addr);

	return 0;
}

static struct kretprobe mf_kretprobe = {
	.entry_handler = entry_handler_mf,
	.handler = ret_handler_mf,
	.data_size = sizeof(struct pf_data)
};

static int register_mf(void)
{
	int ret;

	ret = dbi_register_kretprobe(&mf_kretprobe);
	if (ret)
		printk("dbi_register_kretprobe(handle_mm_fault) ret=%d!\n",
		       ret);

	return ret;
}

static void unregister_mf(void)
{
	dbi_unregister_kretprobe(&mf_kretprobe);
}





/*
 ******************************************************************************
 *                              copy_process()                                *
 ******************************************************************************
 */
static atomic_t copy_process_cnt = ATOMIC_INIT(0);

static void recover_child(struct task_struct *child_task, struct sspt_proc *proc)
{
	sspt_proc_uninstall(proc, child_task, US_DISARM);
	dbi_disarm_urp_inst_for_task(current, child_task);
}

static void rm_uprobes_child(struct task_struct *task)
{
	struct sspt_proc *proc;

	sspt_proc_write_lock();

	proc = sspt_proc_get_by_task(current);
	if (proc)
		recover_child(task, proc);

	sspt_proc_write_unlock();
}

static int entry_handler_cp(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	atomic_inc(&copy_process_cnt);

	if (atomic_read(&stop_flag))
		call_mm_release(current);

	return 0;
}

/* Delete uprobs in children at fork */
static int ret_handler_cp(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = (struct task_struct *)regs_return_value(regs);

	if(!task || IS_ERR(task))
		goto out;

	if(task->mm != current->mm) {	/* check flags CLONE_VM */
		rm_uprobes_child(task);
	}
out:
	atomic_dec(&copy_process_cnt);

	return 0;
}

static struct kretprobe cp_kretprobe = {
	.entry_handler = entry_handler_cp,
	.handler = ret_handler_cp,
};

static int register_cp(void)
{
	int ret;

	ret = dbi_register_kretprobe(&cp_kretprobe);
	if (ret)
		printk("dbi_register_kretprobe(copy_process) ret=%d!\n", ret);

	return ret;
}

static void unregister_cp(void)
{
	dbi_unregister_kretprobe_top(&cp_kretprobe, 0);
	do {
		synchronize_sched();
	} while (atomic_read(&copy_process_cnt));
	dbi_unregister_kretprobe_bottom(&cp_kretprobe);
}





/*
 ******************************************************************************
 *                                mm_release()                                *
 ******************************************************************************
 */

/* Detects when target process removes IPs. */
static int mr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *task = (struct task_struct *)swap_get_karg(regs, 0);

	if (is_kthread(task))
		goto out;

	if (task->tgid != task->pid) {
		/* if the thread is killed we need to discard pending
		 * uretprobe instances which have not triggered yet */
		dbi_discard_pending_uretprobes(task);
		goto out;
	}

	call_mm_release(task);
out:
	return 0;
}

static struct kprobe mr_kprobe = {
	.pre_handler = mr_pre_handler
};

static int register_mr(void)
{
	int ret;

	ret = dbi_register_kprobe(&mr_kprobe);
	if (ret)
		printk("dbi_register_kprobe(mm_release) ret=%d!\n", ret);

	return ret;
}

static void unregister_mr(void)
{
	dbi_unregister_kprobe(&mr_kprobe);
}





/*
 ******************************************************************************
 *                                 do_munmap()                                *
 ******************************************************************************
 */
struct unmap_data {
	unsigned long start;
	size_t len;
};

static atomic_t unmap_cnt = ATOMIC_INIT(0);

static void __remove_unmap_probes(struct sspt_proc *proc,
				  struct unmap_data *umd)
{
	struct task_struct *task = proc->task;
	unsigned long start = umd->start;
	size_t len = PAGE_ALIGN(umd->len);
	LIST_HEAD(head);

	if (sspt_proc_get_files_by_region(proc, &head, start, len)) {
		struct sspt_file *file, *n;
		unsigned long end = start + len;

		list_for_each_entry_safe(file, n, &head, list) {
			if (file->vm_start >= end)
				continue;

			if (file->vm_start >= start) {
				sspt_file_uninstall(file, task, US_UNINSTALL);
			} else {
				/* TODO: uninstall pages: start..file->vm_end */
			}
		}

		sspt_proc_insert_files(proc, &head);

		proc_unmap_msg(start, end);
	}
}

static void remove_unmap_probes(struct task_struct *task,
				struct unmap_data *umd)
{
	struct sspt_proc *proc;

	sspt_proc_write_lock();

	proc = sspt_proc_get_by_task(task);
	if (proc)
		__remove_unmap_probes(proc, umd);

	sspt_proc_write_unlock();
}

static int entry_handler_unmap(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct unmap_data *data = (struct unmap_data *)ri->data;
	struct task_struct *task = current->group_leader;

	atomic_inc(&unmap_cnt);

	data->start = swap_get_karg(regs, 1);
	data->len = (size_t)swap_get_karg(regs, 2);

	if (!is_kthread(task) && atomic_read(&stop_flag))
		remove_unmap_probes(task, data);

	return 0;
}

static int ret_handler_unmap(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	struct task_struct *task;

	task = current->group_leader;
	if (is_kthread(task) ||
	    get_regs_ret_val(regs))
		return 0;

	remove_unmap_probes(task, (struct unmap_data *)ri->data);

	atomic_dec(&unmap_cnt);

	return 0;
}

static struct kretprobe unmap_kretprobe = {
	.entry_handler = entry_handler_unmap,
	.handler = ret_handler_unmap,
	.data_size = sizeof(struct unmap_data)
};

static int register_unmap(void)
{
	int ret;

	ret = dbi_register_kretprobe(&unmap_kretprobe);
	if (ret)
		printk("dbi_register_kprobe(do_munmap) ret=%d!\n", ret);

	return ret;
}

static void unregister_unmap(void)
{
	dbi_unregister_kretprobe_top(&unmap_kretprobe, 0);
	do {
		synchronize_sched();
	} while (atomic_read(&unmap_cnt));
	dbi_unregister_kretprobe_bottom(&unmap_kretprobe);
}





/*
 ******************************************************************************
 *                               do_mmap_pgoff()                              *
 ******************************************************************************
 */
static int ret_handler_mmap(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct sspt_proc *proc;
	struct task_struct *task;
	unsigned long start_addr;
	struct vm_area_struct *vma;

	task = current->group_leader;
	if (is_kthread(task))
		return 0;

	start_addr = (unsigned long)get_regs_ret_val(regs);
	if (IS_ERR_VALUE(start_addr))
		return 0;

	proc = sspt_proc_get_by_task(task);
	if (proc == NULL)
		return 0;

	vma = find_vma_intersection(task->mm, start_addr, start_addr + 1);
	if (vma && check_vma(vma))
		pcoc_map_msg(vma);

	return 0;
}

static struct kretprobe mmap_kretprobe = {
	.handler = ret_handler_mmap
};

static int register_mmap(void)
{
	int ret;

	ret = dbi_register_kretprobe(&mmap_kretprobe);
	if (ret)
		printk("dbi_register_kretprobe(do_mmap_pgoff) ret=%d!\n", ret);

	return ret;
}

static void unregister_mmap(void)
{
	dbi_unregister_kretprobe(&mmap_kretprobe);
}





int register_helper(void)
{
	int ret = 0;

	atomic_set(&stop_flag, 0);

	/* install probe on 'do_munmap' to detect when for remove US probes */
	ret = register_unmap();
	if (ret)
		return ret;

	/* install probe on 'mm_release' to detect when for remove US probes */
	ret = register_mr();
	if (ret)
		goto unreg_unmap;

	/* install probe on 'copy_process' to disarm children process */
	ret = register_cp();
	if (ret)
		goto unreg_mr;

	/* install probe on 'do_mmap_pgoff' to detect when mapping file */
	ret = register_mmap();
	if (ret)
		goto unreg_cp;

	/*
	 * install probe on 'handle_mm_fault' to detect when US pages will be
	 * loaded
	 */
	ret = register_mf();
	if (ret)
		goto unreg_mmap;

	return ret;

unreg_mmap:
	unregister_mmap();

unreg_cp:
	unregister_cp();

unreg_mr:
	unregister_mr();

unreg_unmap:
	unregister_unmap();

	return ret;
}

void unregister_helper_top(void)
{
	unregister_mf();
	atomic_set(&stop_flag, 1);
}

void unregister_helper_bottom(void)
{
	unregister_mmap();
	unregister_cp();
	unregister_mr();
	unregister_unmap();
}

int init_helper(void)
{
	unsigned long addr;
	addr = swap_ksyms("handle_mm_fault");
	if (addr == 0) {
		printk("Cannot find address for handle_mm_fault function!\n");
		return -EINVAL;
	}
	mf_kretprobe.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms_substr("copy_process");
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
	unmap_kretprobe.kp.addr = (kprobe_opcode_t *)addr;

	addr = swap_ksyms("do_mmap_pgoff");
	if (addr == 0) {
		printk("Cannot find address for do_mmap_pgoff function!\n");
		return -EINVAL;
	}
	mmap_kretprobe.kp.addr = (kprobe_opcode_t *)addr;

	return 0;
}

void uninit_helper(void)
{
}
