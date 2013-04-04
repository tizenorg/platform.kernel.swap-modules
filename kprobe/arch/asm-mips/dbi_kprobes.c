/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/arch/asm-mips/dbi_kprobes.c
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
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * 2006-2007    Ekaterina Gorelkina <e.gorelkina@samsung.com>: initial implementation for ARM/MIPS
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user-space and kernel space.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 * 2012		Stanislav Andreev <s.andreev@samsung.com>: added time debug profiling support; BUG() message fix
 */

#include "dbi_kprobes.h"
#include "../dbi_kprobes.h"
#include "../../dbi_kprobes.h"

#include "../../dbi_kdebug.h"
#include "../../dbi_insn_slots.h"
#include "../../dbi_kprobes_deps.h"
#include "../../dbi_uprobes.h"
#include <ksyms.h>

#ifdef OVERHEAD_DEBUG
#include <linux/time.h>
#endif

#define SUPRESS_BUG_MESSAGES

unsigned int *arr_traps_original;

extern struct kprobe * per_cpu__current_kprobe;

#ifdef OVERHEAD_DEBUG
unsigned long swap_sum_time = 0;
unsigned long swap_sum_hit = 0;
EXPORT_SYMBOL_GPL (swap_sum_time);
EXPORT_SYMBOL_GPL (swap_sum_hit);
#endif

unsigned int arr_traps_template[] = {  0x3c010000,   // lui  a1       [0]
	0x24210000,   // addiu a1, a1  [1]
	0x00200008,   // jr a1         [2]
	0x00000000,   // nop
	0xffffffff    // end
};

struct kprobe trampoline_p =
{
	.addr = (kprobe_opcode_t *) & kretprobe_trampoline,
	.pre_handler = trampoline_probe_handler
};

void gen_insn_execbuf(void);

void gen_insn_execbuf_holder (void)
{
	asm volatile (".global gen_insn_execbuf\n"
			"gen_insn_execbuf:\n"
			"nop\n"	                // original instruction
			"nop\n"                 //ssbreak
			"nop\n");               //retbreak
}


int arch_check_insn (struct arch_specific_insn *ainsn)
{
	int ret = 0;

	switch (MIPS_INSN_OPCODE (ainsn->insn[0]))
	{
		case MIPS_BEQ_OPCODE:	//B, BEQ
		case MIPS_BEQL_OPCODE:	//BEQL
		case MIPS_BNE_OPCODE:	//BNE
		case MIPS_BNEL_OPCODE:	//BNEL
		case MIPS_BGTZ_OPCODE:	//BGTZ
		case MIPS_BGTZL_OPCODE:	//BGTZL
		case MIPS_BLEZ_OPCODE:	//BLEZ
		case MIPS_BLEZL_OPCODE:	//BLEZL
		case MIPS_J_OPCODE:	//J
		case MIPS_JAL_OPCODE:	//JAL
			DBPRINTF ("arch_check_insn: opcode");
			ret = -EFAULT;
			break;
		case MIPS_REGIMM_OPCODE:
			//BAL, BGEZ, BGEZAL, BGEZALL, BGEZL, BLTZ, BLTZAL, BLTZALL, BLTZL
			switch (MIPS_INSN_RT (ainsn->insn[0]))
			{
				case MIPS_BLTZ_RT:
				case MIPS_BGEZ_RT:
				case MIPS_BLTZL_RT:
				case MIPS_BGEZL_RT:
				case MIPS_BLTZAL_RT:
				case MIPS_BGEZAL_RT:
				case MIPS_BLTZALL_RT:
				case MIPS_BGEZALL_RT:
					DBPRINTF ("arch_check_insn: REGIMM opcode\n");
					ret = -EFAULT;
					break;
			}
			break;
			//BC1F, BC1FL, BC1T, BC1TL
		case MIPS_COP1_OPCODE:
			//BC2F, BC2FL, BC2T, BC2TL
		case MIPS_COP2_OPCODE:
			if (MIPS_INSN_RS (ainsn->insn[0]) == MIPS_BC_RS)
			{
				DBPRINTF ("arch_check_insn: COP1 opcode\n");
				ret = -EFAULT;
			}
			break;
		case MIPS_SPECIAL_OPCODE:
			//BREAK, JALR, JALR.HB, JR, JR.HB
			switch (MIPS_INSN_FUNC (ainsn->insn[0]))
			{
				case MIPS_JR_FUNC:
				case MIPS_JALR_FUNC:
				case MIPS_BREAK_FUNC:
				case MIPS_SYSCALL_FUNC:
					DBPRINTF ("arch_check_insn: SPECIAL opcode\n");
					ret = -EFAULT;
					break;
			}
			break;
	}
	return ret;
}

int arch_prepare_kprobe (struct kprobe *p)
{
	kprobe_opcode_t insns[KPROBES_TRAMP_LEN];

	int ret = 0;
	if (!ret)
	{
		kprobe_opcode_t insn[MAX_INSN_SIZE];
		struct arch_specific_insn ainsn;
		/* insn: must be on special executable page on i386. */
		p->ainsn.insn = get_insn_slot (NULL, 0);
		if (!p->ainsn.insn)
			return -ENOMEM;
		memcpy (insn, p->addr, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
		ainsn.insn = insn;
		ret = arch_check_insn (&ainsn);
		if (!ret)
		{
			p->opcode = *p->addr;
			p->ainsn.boostable = 0;
			memcpy (insns, gen_insn_execbuf, sizeof (insns));
			insns[KPROBES_TRAMP_INSN_IDX] = insn[0];
			insns[KPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
			insns[KPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
			DBPRINTF ("arch_prepare_kprobe: insn %lx", insn[0]);
			DBPRINTF ("arch_prepare_kprobe: to %p - %lx %lx %lx",
					p->ainsn.insn, insns[0], insns[1], insns[2]);
			memcpy (p->ainsn.insn, insns, sizeof(insns));
		}
		else
		{
			free_insn_slot(&kprobe_insn_pages, NULL, p->ainsn.insn);
		}
	}

	return ret;
}

int arch_prepare_uprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	int ret = 0;
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN];

	if ((unsigned long) p->addr & 0x01)
	{
		DBPRINTF ("Attempt to register kprobe at an unaligned address");
		ret = -EINVAL;
	}

	if (!ret)
	{
		kprobe_opcode_t insn[MAX_INSN_SIZE];
		struct arch_specific_insn ainsn;

		if (!read_proc_vm_atomic (task, (unsigned long) p->addr, &insn, MAX_INSN_SIZE * sizeof(kprobe_opcode_t)))
			panic ("failed to read memory %p!\n", p->addr);
		ainsn.insn = insn;
		ret = arch_check_insn (&ainsn);
		if (!ret)
		{
			p->opcode = insn[0];
			p->ainsn.insn = get_insn_slot(task, atomic);
			if (!p->ainsn.insn)
				return -ENOMEM;
			p->ainsn.boostable = 0;
			memcpy (insns, gen_insn_execbuf, sizeof (insns));
			insns[UPROBES_TRAMP_INSN_IDX] = insn[0];
			insns[UPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
			insns[UPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
			DBPRINTF ("arch_prepare_uprobe: insn %lx", insn[0]);
			DBPRINTF ("arch_prepare_uprobe: to %p - %lx %lx %lx",
					p->ainsn.insn, insns[0], insns[1], insns[2]);

			if (!write_proc_vm_atomic (task, (unsigned long) p->ainsn.insn, insns, sizeof (insns)))
			{
				panic("failed to write memory %p!\n", p->ainsn.insn);
				DBPRINTF ("failed to write insn slot to process memory: insn %p, addr %p, probe %p!", insn, p->ainsn.insn, p->addr);
				/*printk ("failed to write insn slot to process memory: %p/%d insn %lx, addr %p, probe %p!\n",
				  task, task->pid, insn, p->ainsn.insn, p->addr);*/
				free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn);
				return -EINVAL;
			}
		}
	}

	return ret;
}

void prepare_singlestep (struct kprobe *p, struct pt_regs *regs)
{
	if(p->ss_addr)
	{
		regs->cp0_epc = (unsigned long) p->ss_addr;
		p->ss_addr = NULL;
	}
	else
		regs->cp0_epc = (unsigned long) p->ainsn.insn;
}


void save_previous_kprobe (struct kprobe_ctlblk *kcb, struct kprobe *cur_p)
{
	if (kcb->prev_kprobe.kp != NULL)
	{
		panic ("no space to save new probe[]: task = %d/%s, prev %d/%p, current %d/%p, new %d/%p,",
				current->pid, current->comm, kcb->prev_kprobe.kp->tgid, kcb->prev_kprobe.kp->addr,
				kprobe_running()->tgid, kprobe_running()->addr, cur_p->tgid, cur_p->addr);
	}

	kcb->prev_kprobe.kp = kprobe_running ();
	kcb->prev_kprobe.status = kcb->kprobe_status;
}

void restore_previous_kprobe (struct kprobe_ctlblk *kcb)
{
	__get_cpu_var (current_kprobe) = kcb->prev_kprobe.kp;
	kcb->kprobe_status = kcb->prev_kprobe.status;
	kcb->prev_kprobe.kp = NULL;
	kcb->prev_kprobe.status = 0;
}

void set_current_kprobe (struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
{
	__get_cpu_var (current_kprobe) = p;
	DBPRINTF ("set_current_kprobe[]: p=%p addr=%p\n", p, p->addr);
}

int kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *p = 0;
	int ret = 0, pid = 0, retprobe = 0, reenter = 0;
	kprobe_opcode_t *addr = NULL, *ssaddr = 0;
	struct kprobe_ctlblk *kcb;
#ifdef OVERHEAD_DEBUG
	struct timeval swap_tv1;
	struct timeval swap_tv2;
#endif
#ifdef SUPRESS_BUG_MESSAGES
	int swap_oops_in_progress;
#endif

	/* We're in an interrupt, but this is clear and BUG()-safe. */

	addr = (kprobe_opcode_t *) regs->cp0_epc;
	DBPRINTF ("regs->regs[ 31 ] = 0x%lx\n", regs->regs[31]);

#ifdef SUPRESS_BUG_MESSAGES
	// oops_in_progress used to avoid BUG() messages that slow down kprobe_handler() execution
	swap_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
#endif
#ifdef OVERHEAD_DEBUG
#define USEC_IN_SEC_NUM				1000000
	do_gettimeofday(&swap_tv1);
#endif
	preempt_disable ();

	kcb = get_kprobe_ctlblk ();

	if (user_mode (regs))
	{
		//DBPRINTF("exception[%lu] from user mode %s/%u addr %p (%lx).", nCount, current->comm, current->pid, addr, regs->uregs[14]);
		pid = current->tgid;
	}

	/* Check we're not actually recursing */
	if (kprobe_running ())
	{
		DBPRINTF ("lock???");
		p = get_kprobe(addr, pid);
		if (p)
		{
			if(!pid && (addr == (kprobe_opcode_t *)kretprobe_trampoline)){
				save_previous_kprobe (kcb, p);
				kcb->kprobe_status = KPROBE_REENTER;
				reenter = 1;
			}
			else {
				/* We have reentered the kprobe_handler(), since
				 * another probe was hit while within the handler.
				 * We here save the original kprobes variables and
				 * just single step on the instruction of the new probe
				 * without calling any user handlers.
				 */
				if(!p->ainsn.boostable){
					save_previous_kprobe (kcb, p);
					set_current_kprobe (p, regs, kcb);
				}
				kprobes_inc_nmissed_count (p);
				prepare_singlestep (p, regs);
				if(!p->ainsn.boostable)
					kcb->kprobe_status = KPROBE_REENTER;
				preempt_enable_no_resched ();
#ifdef OVERHEAD_DEBUG
				do_gettimeofday(&swap_tv2);
				swap_sum_hit++;
				swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) * USEC_IN_SEC_NUM +
					(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
				oops_in_progress = swap_oops_in_progress;
#endif
				return 1;
			}
		}
		else
		{
			if(pid) { //we can reenter probe upon uretprobe exception
				DBPRINTF ("check for UNDEF_INSTRUCTION %p\n", addr);
				// UNDEF_INSTRUCTION from user space
				p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
				if (p) {
					save_previous_kprobe (kcb, p);
					kcb->kprobe_status = KPROBE_REENTER;
					reenter = 1;
					retprobe = 1;
					DBPRINTF ("uretprobe %p\n", addr);
				}
			}
			if(!p) {
				p = __get_cpu_var (current_kprobe);
				DBPRINTF ("kprobe_running !!! p = 0x%p p->break_handler = 0x%p", p, p->break_handler);
				/*if (p->break_handler && p->break_handler(p, regs)) {
				  DBPRINTF("kprobe_running !!! goto ss");
				  goto ss_probe;
				  } */
				DBPRINTF ("unknown uprobe at %p cur at %p/%p\n", addr, p->addr, p->ainsn.insn);
				if(pid)
					ssaddr = p->ainsn.insn + UPROBES_TRAMP_SS_BREAK_IDX;
				else
					ssaddr = p->ainsn.insn + KPROBES_TRAMP_SS_BREAK_IDX;
				if (addr == ssaddr)
				{
					regs->cp0_epc = (unsigned long) (p->addr + 1);
					DBPRINTF ("finish step at %p cur at %p/%p, redirect to %lx\n", addr, p->addr, p->ainsn.insn, regs->cp0_epc);

					if (kcb->kprobe_status == KPROBE_REENTER) {
						restore_previous_kprobe (kcb);
					}
					else {
						reset_current_kprobe ();
					}
				}
				DBPRINTF ("kprobe_running !!! goto no");
				ret = 1;
				/* If it's not ours, can't be delete race, (we hold lock). */
				DBPRINTF ("no_kprobe");
				goto no_kprobe;
			}
		}
	}

	//if(einsn != UNDEF_INSTRUCTION) {
	DBPRINTF ("get_kprobe %p-%d", addr, pid);
	if (!p)
		p = get_kprobe(addr, pid);
	if (!p)
	{
		if(pid) {
			DBPRINTF ("search UNDEF_INSTRUCTION %p\n", addr);
			// UNDEF_INSTRUCTION from user space
			p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
			if (!p) {
				/* Not one of ours: let kernel handle it */
				DBPRINTF ("no_kprobe");
				//printk("no_kprobe2 ret = %d\n", ret);
				goto no_kprobe;
			}
			retprobe = 1;
			DBPRINTF ("uretprobe %p\n", addr);
		}
		else {
			/* Not one of ours: let kernel handle it */
			DBPRINTF ("no_kprobe");
			//printk("no_kprobe2 ret = %d\n", ret);
			goto no_kprobe;
		}
	}

	set_current_kprobe (p, regs, kcb);
	if(!reenter)
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;

	if (retprobe)		//(einsn == UNDEF_INSTRUCTION)
		ret = trampoline_probe_handler (p, regs);
	else if (p->pre_handler)
	{
		ret = p->pre_handler (p, regs);
		if(!p->ainsn.boostable)
			kcb->kprobe_status = KPROBE_HIT_SS;
		else if(p->pre_handler != trampoline_probe_handler) {
#ifdef SUPRESS_BUG_MESSAGES
			preempt_disable();
#endif
			reset_current_kprobe ();
#ifdef SUPRESS_BUG_MESSAGES
			preempt_enable_no_resched();
#endif
		}
	}

	if (ret)
	{
		DBPRINTF ("p->pre_handler[] 1");
#ifdef OVERHEAD_DEBUG
		do_gettimeofday(&swap_tv2);
		swap_sum_hit++;
		swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) * USEC_IN_SEC_NUM +
			(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
		oops_in_progress = swap_oops_in_progress;
#endif
		/* handler has already set things up, so skip ss setup */
		return 1;
	}
	DBPRINTF ("p->pre_handler 0");

no_kprobe:
	preempt_enable_no_resched ();
#ifdef OVERHEAD_DEBUG
	do_gettimeofday(&swap_tv2);
	swap_sum_hit++;
	swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) * USEC_IN_SEC_NUM +
		(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
	oops_in_progress = swap_oops_in_progress;
#endif
	return ret;
}

void patch_suspended_task_ret_addr(struct task_struct *p, struct kretprobe *rp)
{
	DBPRINTF("patch_suspended_task_ret_addr is not implemented");
}

int setjmp_pre_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of (p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry;
	entry_point_t entry;

	DBPRINTF ("pjp = 0x%p jp->entry = 0x%p", jp, jp->entry);
	entry = (entry_point_t) jp->entry;
	pre_entry = (kprobe_pre_entry_handler_t) jp->pre_entry;
	//if(!entry)
	//      DIE("entry NULL", regs)
	DBPRINTF ("entry = 0x%p jp->entry = 0x%p", entry, jp->entry);

	//call handler for all kernel probes and user space ones which belong to current tgid
	if (!p->tgid || (p->tgid == current->tgid))
	{
		if(!p->tgid && (p->addr == sched_addr) && sched_rp){
			struct task_struct *p, *g;
			rcu_read_lock();
			//swapper task
			if(current != &init_task)
				patch_suspended_task_ret_addr(&init_task, sched_rp);
			// other tasks
			do_each_thread(g, p){
				if(p == current)
					continue;
				patch_suspended_task_ret_addr(p, sched_rp);
			} while_each_thread(g, p);
			rcu_read_unlock();
		}
		if (pre_entry)
			p->ss_addr = (void *)pre_entry (jp->priv_arg, regs);
		if (entry){
			entry (regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7], regs->regs[8], regs->regs[9]);
		}
		else {
			if (p->tgid)
				dbi_arch_uprobe_return ();
			else
				dbi_jprobe_return ();
		}
	}
	else if (p->tgid)
		dbi_arch_uprobe_return ();

	prepare_singlestep (p, regs);

	return 1;
}


void dbi_jprobe_return (void)
{
	preempt_enable_no_resched();
}

void dbi_arch_uprobe_return (void)
{
	preempt_enable_no_resched();
}

int longjmp_break_handler (struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

void arch_arm_kprobe (struct kprobe *p)
{
	*p->addr = BREAKPOINT_INSTRUCTION;
	flush_icache_range ((unsigned long) p->addr, (unsigned long) p->addr + sizeof (kprobe_opcode_t));
}

void arch_disarm_kprobe (struct kprobe *p)
{
	*p->addr = p->opcode;
	flush_icache_range ((unsigned long) p->addr, (unsigned long) p->addr + sizeof (kprobe_opcode_t));
}

int trampoline_probe_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe_instance *ri = NULL;
	struct hlist_head *head, empty_rp;
	struct hlist_node *node, *tmp;
	unsigned long flags, orig_ret_address = 0;
	unsigned long trampoline_address = (unsigned long) &kretprobe_trampoline;
	struct kretprobe *crp = NULL;
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	DBPRINTF ("start");

	if (p && p->tgid){
		// in case of user space retprobe trampoline is at the Nth instruction of US tramp
		trampoline_address = (unsigned long)(p->ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
	}

	INIT_HLIST_HEAD (&empty_rp);
	spin_lock_irqsave (&kretprobe_lock, flags);
	head = kretprobe_inst_table_head (current);

	/*
	 * It is possible to have multiple instances associated with a given
	 * task either because an multiple functions in the call path
	 * have a return probe installed on them, and/or more then one
	 * return probe was registered for a target function.
	 *
	 * We can handle this because:
	 *     - instances are always inserted at the head of the list
	 *     - when multiple return probes are registered for the same
	 *       function, the first instance's ret_addr will point to the
	 *       real return address, and all the rest will point to
	 *       kretprobe_trampoline
	 */
	hlist_for_each_entry_safe (ri, node, tmp, head, hlist)
	{
		if (ri->task != current)
			/* another task is sharing our hash bucket */
			continue;
		if (ri->rp && ri->rp->handler){
			ri->rp->handler (ri, regs, ri->rp->priv_arg);

		}

		orig_ret_address = (unsigned long) ri->ret_addr;
		recycle_rp_inst (ri);
		if (orig_ret_address != trampoline_address)
			/*
			 * This is the real return address. Any other
			 * instances associated with this task are for
			 * other calls deeper on the call stack
			 */
			break;
	}
	kretprobe_assert (ri, orig_ret_address, trampoline_address);
	//BUG_ON(!orig_ret_address || (orig_ret_address == trampoline_address));
	if (trampoline_address != (unsigned long) &kretprobe_trampoline){
		if (ri->rp) BUG_ON (ri->rp->kp.tgid == 0);
	}
	if (ri->rp && ri->rp->kp.tgid)
		BUG_ON (trampoline_address == (unsigned long) &kretprobe_trampoline);

	regs->regs[31] = orig_ret_address;
	DBPRINTF ("regs->cp0_epc = 0x%lx", regs->cp0_epc);
	if (trampoline_address != (unsigned long) &kretprobe_trampoline)
		regs->cp0_epc = orig_ret_address;
	else
		regs->cp0_epc = regs->cp0_epc + 4;
	DBPRINTF ("regs->cp0_epc = 0x%lx", regs->cp0_epc);
	DBPRINTF ("regs->cp0_status = 0x%lx", regs->cp0_status);

	if(p){ // ARM, MIPS, X86 user space
		if (kcb->kprobe_status == KPROBE_REENTER)
			restore_previous_kprobe (kcb);
		else
			reset_current_kprobe ();
	}

	spin_unlock_irqrestore (&kretprobe_lock, flags);
	hlist_for_each_entry_safe (ri, node, tmp, &empty_rp, hlist)
	{
		hlist_del (&ri->hlist);
		kfree (ri);
	}
	preempt_enable_no_resched ();
	/*
	 * By returning a non-zero value, we are telling
	 * kprobe_handler() that we don't want the post_handler
	 * to run (and have re-enabled preemption)
	 */
	return 1;
}

void arch_prepare_kretprobe(struct kretprobe *rp, struct pt_regs *regs)
{

	struct kretprobe_instance *ri;

	DBPRINTF ("start\n");
	//TODO: test - remove retprobe after func entry but before its exit
	if ((ri = get_free_rp_inst (rp)) != NULL)
	{
		ri->rp = rp;
		ri->task = current;
		ri->ret_addr = (kprobe_opcode_t *) regs->regs[31];
		if (rp->kp.tgid)
			regs->regs[31] = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
		else	/* Replace the return addr with trampoline addr */
			regs->regs[31] = (unsigned long) &kretprobe_trampoline;
		add_rp_inst (ri);
	}
	else {
		DBPRINTF ("WARNING: missed retprobe %p\n", rp->kp.addr);
		rp->nmissed++;
	}
}

DECLARE_MOD_CB_DEP(flush_icache_range, \
		void, unsigned long __user start, unsigned long __user end);
DECLARE_MOD_CB_DEP(flush_icache_page, \
		void, struct vm_area_struct * vma, struct page * page);
DECLARE_MOD_CB_DEP(flush_cache_page, \
		void, struct vm_area_struct * vma, unsigned long page);

int arch_init_module_deps()
{
	INIT_MOD_DEP_CB(flush_icache_range, r4k_flush_icache_range);
	INIT_MOD_DEP_CB(flush_icache_page, r4k_flush_icache_page);
	INIT_MOD_DEP_CB(flush_cache_page, r4k_flush_cache_page);

	return 0;
}


int __init arch_init_kprobes (void)
{
	unsigned int do_bp_handler;
	unsigned int kprobe_handler_addr;

	unsigned int insns_num = 0;
	unsigned int code_size = 0;

	unsigned int reg_hi;
	unsigned int reg_lo;

	int ret;

	if (arch_init_module_dependencies())
	{
		DBPRINTF ("Unable to init module dependencies\n");
		return -1;
	}

	do_bp_handler = (unsigned int)swap_ksyms("do_bp");

	kprobe_handler_addr = (unsigned int) &kprobe_handler;
	insns_num = sizeof (arr_traps_template) / sizeof (arr_traps_template[0]);
	code_size = insns_num * sizeof (unsigned int);
	DBPRINTF ("insns_num = %d\n", insns_num);
	// Save original code
	arr_traps_original = kmalloc (code_size, GFP_KERNEL);
	if (!arr_traps_original)
	{
		DBPRINTF ("Unable to allocate space for original code of <do_bp>!\n");
		return -1;
	}
	memcpy (arr_traps_original, (void *) do_bp_handler, code_size);

	reg_hi = HIWORD (kprobe_handler_addr);
	reg_lo = LOWORD (kprobe_handler_addr);
	if (reg_lo >= 0x8000)
		reg_hi += 0x0001;
	arr_traps_template[REG_HI_INDEX] |= reg_hi;
	arr_traps_template[REG_LO_INDEX] |= reg_lo;

	// Insert new code
	memcpy ((void *) do_bp_handler, arr_traps_template, code_size);
	flush_icache_range (do_bp_handler, do_bp_handler + code_size);
	if((ret = dbi_register_kprobe (&trampoline_p)) != 0){
		//dbi_unregister_jprobe(&do_exit_p, 0);
		return ret;
	}
}

void __exit dbi_arch_exit_kprobes (void)
{
	unsigned int do_bp_handler;

	unsigned int insns_num = 0;
	unsigned int code_size = 0;

	// Get instruction address
	do_bp_handler = (unsigned int)swap_ksyms("do_undefinstr");

	//dbi_unregister_jprobe(&do_exit_p, 0);

	// Replace back the original code

	insns_num = sizeof (arr_traps_template) / sizeof (arr_traps_template[0]);
	code_size = insns_num * sizeof (unsigned int);
	memcpy ((void *) do_bp_handler, arr_traps_original, code_size);
	flush_icache_range (do_bp_handler, do_bp_handler + code_size);
	kfree (arr_traps_original);
	arr_traps_original = NULL;
}

//EXPORT_SYMBOL_GPL (dbi_arch_uprobe_return);
//EXPORT_SYMBOL_GPL (dbi_arch_exit_kprobes);

