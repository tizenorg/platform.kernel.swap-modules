/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/arch/asm-arm/dbi_kprobes.c
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
 *              Probes initial implementation; Support x86.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 * 2010-2011    Alexander Shirshikov <a.shirshikov@samsung.com>: initial implementation for Thumb
 * 2012         Stanislav Andreev <s.andreev@samsung.com>: added time debug profiling support; BUG() message fix
 * 2012         Stanislav Andreev <s.andreev@samsung.com>: redesign of kprobe functionality -
 *              kprobe_handler() now called via undefined instruction hooks
 * 2012         Stanislav Andreev <s.andreev@samsung.com>: hash tables search implemented for uprobes
 */

#include <linux/module.h>
#include <linux/mm.h>

#include "dbi_kprobes.h"
#include "dbi_kprobes_arm.h"
#include "dbi_kprobes_thumb.h"
#include "../dbi_kprobes.h"
#include "../../dbi_kprobes.h"

#include "../../dbi_kdebug.h"
#include "../../dbi_insn_slots.h"
#include "../../dbi_kprobes_deps.h"
#include <ksyms.h>

#include <asm/cacheflush.h>

#ifdef TRAP_OVERHEAD_DEBUG
#include <linux/pid.h>
#include <linux/signal.h>
#endif

#ifdef OVERHEAD_DEBUG
#include <linux/time.h>
#endif

#include <asm/traps.h>
#include <asm/ptrace.h>
#include <linux/list.h>
#include <linux/hash.h>

#define SUPRESS_BUG_MESSAGES

extern struct kprobe * per_cpu__current_kprobe;
extern struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];

static void (*__swap_register_undef_hook)(struct undef_hook *hook);
static void (*__swap_unregister_undef_hook)(struct undef_hook *hook);

#ifdef OVERHEAD_DEBUG
unsigned long swap_sum_time = 0;
unsigned long swap_sum_hit = 0;
EXPORT_SYMBOL_GPL (swap_sum_time);
EXPORT_SYMBOL_GPL (swap_sum_hit);
#endif

static unsigned int arr_traps_template[] = {
		0xe1a0c00d,    // mov          ip, sp
		0xe92dd800,    // stmdb        sp!, {fp, ip, lr, pc}
		0xe24cb004,    // sub          fp, ip, #4      ; 0x4
		0x00000000,    // b
		0xe3500000,    // cmp          r0, #0  ; 0x0
		0xe89da800,    // ldmia        sp, {fp, sp, pc}
		0x00000000,    // nop
		0xffffffff     // end
};


static struct kprobe trampoline_p =
{
	.addr = (kprobe_opcode_t *) & kretprobe_trampoline,
	.pre_handler = trampoline_probe_handler
};

int prep_pc_dep_insn_execbuf(kprobe_opcode_t *insns, kprobe_opcode_t insn, int uregs)
{
	int i;

	if (uregs & 0x10)
	{
		int reg_mask = 0x1;
		//search in reg list
		for (i = 0; i < 13; i++, reg_mask <<= 1)
		{
			if (!(insn & reg_mask))
				break;
		}
	}
	else
	{
		for (i = 0; i < 13; i++)
		{
			if ((uregs & 0x1) && (ARM_INSN_REG_RN (insn) == i))
				continue;
			if ((uregs & 0x2) && (ARM_INSN_REG_RD (insn) == i))
				continue;
			if ((uregs & 0x4) && (ARM_INSN_REG_RS (insn) == i))
				continue;
			if ((uregs & 0x8) && (ARM_INSN_REG_RM (insn) == i))
				continue;
			break;
		}
	}
	if (i == 13)
	{
		DBPRINTF ("there are no free register %x in insn %lx!", uregs, insn);
		return -EINVAL;
	}
	DBPRINTF ("prep_pc_dep_insn_execbuf: using R%d, changing regs %x", i, uregs);

	// set register to save
	ARM_INSN_REG_SET_RD (insns[0], i);
	// set register to load address to
	ARM_INSN_REG_SET_RD (insns[1], i);
	// set instruction to execute and patch it
	if (uregs & 0x10)
	{
		ARM_INSN_REG_CLEAR_MR (insn, 15);
		ARM_INSN_REG_SET_MR (insn, i);
	}
	else
	{
		if ((uregs & 0x1) && (ARM_INSN_REG_RN (insn) == 15))
			ARM_INSN_REG_SET_RN (insn, i);
		if ((uregs & 0x2) && (ARM_INSN_REG_RD (insn) == 15))
			ARM_INSN_REG_SET_RD (insn, i);
		if ((uregs & 0x4) && (ARM_INSN_REG_RS (insn) == 15))
			ARM_INSN_REG_SET_RS (insn, i);
		if ((uregs & 0x8) && (ARM_INSN_REG_RM (insn) == 15))
			ARM_INSN_REG_SET_RM (insn, i);
	}
	insns[UPROBES_TRAMP_INSN_IDX] = insn;
	// set register to restore
	ARM_INSN_REG_SET_RD (insns[3], i);
	return 0;
}
EXPORT_SYMBOL_GPL(prep_pc_dep_insn_execbuf);

int arch_check_insn_arm(struct arch_specific_insn *ainsn)
{
	int ret = 0;

	// check instructions that can change PC by nature
	if (
//		ARM_INSN_MATCH (UNDEF, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (AUNDEF, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (SWI, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (BREAK, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (BL, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (BLX1, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (BLX2, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (BX, ainsn->insn_arm[0]) ||
		ARM_INSN_MATCH (BXJ, ainsn->insn_arm[0]))
	{
		DBPRINTF ("Bad insn arch_check_insn_arm: %lx\n", ainsn->insn_arm[0]);
		ret = -EFAULT;
	}
#ifndef CONFIG_CPU_V7
	// check instructions that can write result to PC
	else if ((ARM_INSN_MATCH (DPIS, ainsn->insn_arm[0]) ||
				ARM_INSN_MATCH (DPRS, ainsn->insn_arm[0]) ||
				ARM_INSN_MATCH (DPI, ainsn->insn_arm[0]) ||
				ARM_INSN_MATCH (LIO, ainsn->insn_arm[0]) ||
				ARM_INSN_MATCH (LRO, ainsn->insn_arm[0])) &&
			(ARM_INSN_REG_RD (ainsn->insn_arm[0]) == 15))
	{
		DBPRINTF ("Bad arch_check_insn_arm: %lx\n", ainsn->insn_arm[0]);
		ret = -EFAULT;
	}
#endif // CONFIG_CPU_V7
	// check special instruction loads store multiple registers
	else if ((ARM_INSN_MATCH (LM, ainsn->insn_arm[0]) || ARM_INSN_MATCH (SM, ainsn->insn_arm[0])) &&
			// store pc or load to pc
			(ARM_INSN_REG_MR (ainsn->insn_arm[0], 15) ||
			 // store/load with pc update
			 ((ARM_INSN_REG_RN (ainsn->insn_arm[0]) == 15) && (ainsn->insn_arm[0] & 0x200000))))
	{
		DBPRINTF ("Bad insn arch_check_insn_arm: %lx\n", ainsn->insn_arm[0]);
		ret = -EFAULT;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(arch_check_insn_arm);

int arch_prepare_kretprobe (struct kretprobe *p)
{
	DBPRINTF("Warrning: arch_prepare_kretprobe is not implemented\n");
	return 0;
}

int arch_prepare_kprobe (struct kprobe *p)
{
	kprobe_opcode_t insns[KPROBES_TRAMP_LEN];
	int uregs, pc_dep, ret = 0;
    kprobe_opcode_t insn[MAX_INSN_SIZE];
    struct arch_specific_insn ainsn;

    /* insn: must be on special executable page on i386. */
    p->ainsn.insn = get_insn_slot(NULL, &kprobe_insn_pages, 0);
    if (!p->ainsn.insn)
        return -ENOMEM;

    memcpy (insn, p->addr, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
    ainsn.insn_arm = ainsn.insn = insn;
    ret = arch_check_insn_arm (&ainsn);
    if (!ret)
    {
        p->opcode = *p->addr;
        uregs = pc_dep = 0;

        // Rn, Rm ,Rd
        if(ARM_INSN_MATCH (DPIS, insn[0]) || ARM_INSN_MATCH (LRO, insn[0]) ||
           ARM_INSN_MATCH (SRO, insn[0]))
        {
            uregs = 0xb;
            if( (ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) ||
                (ARM_INSN_MATCH (SRO, insn[0]) && (ARM_INSN_REG_RD (insn[0]) == 15)) )
            {
                DBPRINTF ("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
                pc_dep = 1;
            }
        }
        // Rn ,Rd
        else if(ARM_INSN_MATCH (DPI, insn[0]) || ARM_INSN_MATCH (LIO, insn[0]) ||
                ARM_INSN_MATCH (SIO, insn[0]))
        {
            uregs = 0x3;
            if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_MATCH (SIO, insn[0]) &&
                        (ARM_INSN_REG_RD (insn[0]) == 15)))
            {
                pc_dep = 1;
                DBPRINTF ("Unboostable insn %lx/%p, DPI/LIO/SIO\n", insn[0], p);
            }
        }
        // Rn, Rm, Rs
        else if(ARM_INSN_MATCH (DPRS, insn[0]))
        {
            uregs = 0xd;
            if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) ||
                (ARM_INSN_REG_RS (insn[0]) == 15))
            {
                pc_dep = 1;
                DBPRINTF ("Unboostable insn %lx, DPRS\n", insn[0]);
            }
        }
        // register list
        else if(ARM_INSN_MATCH (SM, insn[0]))
        {
            uregs = 0x10;
            if (ARM_INSN_REG_MR (insn[0], 15))
            {
                DBPRINTF ("Unboostable insn %lx, SM\n", insn[0]);
                pc_dep = 1;
            }
        }
        // check instructions that can write result to SP andu uses PC
        if (pc_dep  && (ARM_INSN_REG_RD (ainsn.insn[0]) == 13))
        {
            free_insn_slot(&kprobe_insn_pages, NULL, p->ainsn.insn);
            ret = -EFAULT;
        }
        else
        {
            if (uregs && pc_dep)
            {
                memcpy (insns, pc_dep_insn_execbuf, sizeof (insns));
                if (prep_pc_dep_insn_execbuf (insns, insn[0], uregs) != 0)
                {
                    DBPRINTF ("failed to prepare exec buffer for insn %lx!", insn[0]);
                    free_insn_slot(&kprobe_insn_pages, NULL, p->ainsn.insn);
                    return -EINVAL;
                }
                insns[6] = (kprobe_opcode_t) (p->addr + 2);
            }
            else
            {
                memcpy (insns, gen_insn_execbuf, sizeof (insns));
                insns[KPROBES_TRAMP_INSN_IDX] = insn[0];
            }
            insns[7] = (kprobe_opcode_t) (p->addr + 1);
            DBPRINTF ("arch_prepare_kprobe: insn %lx", insn[0]);
            DBPRINTF ("arch_prepare_kprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx",
                    p->ainsn.insn, insns[0], insns[1], insns[2], insns[3], insns[4],
                    insns[5], insns[6], insns[7], insns[8]);
            memcpy (p->ainsn.insn, insns, sizeof(insns));
            flush_icache_range((long unsigned)p->ainsn.insn, (long unsigned)(p->ainsn.insn) + sizeof(insns));
#ifdef BOARD_tegra
            flush_cache_all();
#endif
        }
    }
    else
    {
        free_insn_slot(&kprobe_insn_pages, NULL, p->ainsn.insn);
        printk("arch_prepare_kprobe: instruction 0x%lx not instrumentation, addr=0x%p\n", insn[0], p->addr);
    }

    return ret;
}

static unsigned int arch_construct_brunch (unsigned int base, unsigned int addr, int link)
{
	kprobe_opcode_t insn;
	unsigned int bpi = (unsigned int) base - (unsigned int) addr - 8;

	insn = bpi >> 2;
	DBPRINTF ("base=%x addr=%x base-addr-8=%x\n", base, addr, bpi);
	if (abs (insn & 0xffffff) > 0xffffff)
	{
		DBPRINTF ("ERROR: kprobe address out of range\n");
		BUG ();
	}
	insn = insn & 0xffffff;
	insn = insn | ((link != 0) ? 0xeb000000 : 0xea000000);
	DBPRINTF ("insn=%lX\n", insn);
	return (unsigned int) insn;
}

int arch_prepare_uretprobe (struct kretprobe *p, struct task_struct *task)
{
	DBPRINTF("Warrning: arch_prepare_uretprobe is not implemented\n");
	return 0;
}
EXPORT_SYMBOL_GPL(arch_prepare_uretprobe);

void prepare_singlestep (struct kprobe *p, struct pt_regs *regs)
{
	if (p->ss_addr) {
		regs->ARM_pc = (unsigned long)p->ss_addr;
		p->ss_addr = NULL;
	} else {
		regs->ARM_pc = (unsigned long)p->ainsn.insn;
	}
}

void save_previous_kprobe(struct kprobe_ctlblk *kcb, struct kprobe *p_run)
{
	if (p_run == NULL) {
		panic("arm_save_previous_kprobe: p_run == NULL\n");
	}

	if (kcb->prev_kprobe.kp != NULL) {
		DBPRINTF ("no space to save new probe[]: task = %d/%s", current->pid, current->comm);
	}

	kcb->prev_kprobe.kp = p_run;
	kcb->prev_kprobe.status = kcb->kprobe_status;
}

void restore_previous_kprobe(struct kprobe_ctlblk *kcb)
{
	set_current_kprobe(kcb->prev_kprobe.kp, NULL, NULL);
	kcb->kprobe_status = kcb->prev_kprobe.status;
	kcb->prev_kprobe.kp = NULL;
	kcb->prev_kprobe.status = 0;
}

void set_current_kprobe(struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
{
	__get_cpu_var(current_kprobe) = p;
	DBPRINTF ("set_current_kprobe: p=%p addr=%p\n", p, p->addr);
}
EXPORT_SYMBOL_GPL(set_current_kprobe);

#ifdef TRAP_OVERHEAD_DEBUG
static unsigned long trap_handler_counter_debug = 0;
#define SAMPLING_COUNTER                               100000
#endif

static int kprobe_handler(struct pt_regs *regs)
{
	int err_out = 0;
	char *msg_out = NULL;
	kprobe_opcode_t *addr = (kprobe_opcode_t *) (regs->ARM_pc);

	struct kprobe *p = NULL, *p_run = NULL;
	int ret = 0, retprobe = 0, reenter = 0;
	kprobe_opcode_t *ssaddr = NULL;
	struct kprobe_ctlblk *kcb;

#ifdef SUPRESS_BUG_MESSAGES
	int swap_oops_in_progress;
	// oops_in_progress used to avoid BUG() messages that slow down kprobe_handler() execution
	swap_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
#endif
#ifdef TRAP_OVERHEAD_DEBUG
	trap_handler_counter_debug++;
	if ( trap_handler_counter_debug < SAMPLING_COUNTER ) {
		err_out = 0;
	}
	else {
		// XXX NOTE - user must care about catching signal via signal handler to avoid hanging!
		printk("Trap %ld reached - send SIGUSR1\n", trap_handler_counter_debug);
		kill_pid(get_task_pid(current, PIDTYPE_PID), SIGUSR1, 1);
		trap_handler_counter_debug = 0;
		err_out = 0;
	}
	return err_out;
#endif
#ifdef OVERHEAD_DEBUG
	struct timeval swap_tv1;
	struct timeval swap_tv2;
#define USEC_IN_SEC_NUM				1000000
	do_gettimeofday(&swap_tv1);
#endif
	preempt_disable();

	p = get_kprobe(addr, 0);

	/* We're in an interrupt, but this is clear and BUG()-safe. */
	kcb = get_kprobe_ctlblk ();

	/* Check we're not actually recursing */
	// TODO: event is not saving in trace
	p_run = kprobe_running();
	if (p_run)
	{
		DBPRINTF("lock???");
		if (p)
		{
			if (addr == (kprobe_opcode_t *)kretprobe_trampoline) {
				save_previous_kprobe(kcb, p_run);
				kcb->kprobe_status = KPROBE_REENTER;
				reenter = 1;
			} else {
				/* We have reentered the kprobe_handler(), since
				 * another probe was hit while within the handler.
				 * We here save the original kprobes variables and
				 * just single step on the instruction of the new probe
				 * without calling any user handlers.
				 */
				kprobes_inc_nmissed_count (p);
				prepare_singlestep (p, regs);

				err_out = 0;
				goto out;
			}
		} else {
			if(!p) {
				p = p_run;
				DBPRINTF ("kprobe_running !!! p = 0x%p p->break_handler = 0x%p", p, p->break_handler);
				/*if (p->break_handler && p->break_handler(p, regs)) {
				  DBPRINTF("kprobe_running !!! goto ss");
				  goto ss_probe;
				  } */
				DBPRINTF ("unknown uprobe at %p cur at %p/%p\n", addr, p->addr, p->ainsn.insn);
				ssaddr = p->ainsn.insn + KPROBES_TRAMP_SS_BREAK_IDX;
				if (addr == ssaddr) {
					regs->ARM_pc = (unsigned long) (p->addr + 1);
					DBPRINTF ("finish step at %p cur at %p/%p, redirect to %lx\n", addr, p->addr, p->ainsn.insn, regs->ARM_pc);
					if (kcb->kprobe_status == KPROBE_REENTER) {
						restore_previous_kprobe(kcb);
					} else {
						reset_current_kprobe();
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

	if (!p) {
		/* Not one of ours: let kernel handle it */
		DBPRINTF ("no_kprobe");
		goto no_kprobe;
	}

	set_current_kprobe(p, NULL, NULL);
	if(!reenter)
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;
	if (retprobe) {		//(einsn == UNDEF_INSTRUCTION)
		ret = trampoline_probe_handler (p, regs);
	} else if (p->pre_handler) {
		ret = p->pre_handler (p, regs);
		if(p->pre_handler != trampoline_probe_handler) {
			reset_current_kprobe();
		}
	}

	if (ret) {
		/* handler has already set things up, so skip ss setup */
		err_out = 0;
		goto out;
	}

no_kprobe:
	msg_out = "no_kprobe\n";
	err_out = 1; 		// return with death
	goto out;

out:
	preempt_enable_no_resched();
#ifdef OVERHEAD_DEBUG
	do_gettimeofday(&swap_tv2);
	swap_sum_hit++;
	swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) *  USEC_IN_SEC_NUM +
		(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
	oops_in_progress = swap_oops_in_progress;
#endif

	if(msg_out) {
		printk(msg_out);
	}

	return err_out;
}

int kprobe_trap_handler(struct pt_regs *regs, unsigned int instr)
{
	int ret;
	unsigned long flags;
	local_irq_save(flags);
	ret = kprobe_handler(regs);
	local_irq_restore(flags);
	return ret;
}

int setjmp_pre_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of (p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry;
	entry_point_t entry;

# ifdef REENTER
//	p = kprobe_running(regs);
# endif

	DBPRINTF ("pjp = 0x%p jp->entry = 0x%p", jp, jp->entry);
	entry = (entry_point_t) jp->entry;
	pre_entry = (kprobe_pre_entry_handler_t) jp->pre_entry;
	//if(!entry)
	//      DIE("entry NULL", regs)
	DBPRINTF ("entry = 0x%p jp->entry = 0x%p", entry, jp->entry);

	//call handler for all kernel probes and user space ones which belong to current tgid
	if (!p->tgid || (p->tgid == current->tgid))
	{
		if(!p->tgid && ((unsigned int)p->addr == sched_addr) && sched_rp) {
			struct thread_info *tinfo = (struct thread_info *)regs->ARM_r2;
			patch_suspended_task(sched_rp, tinfo->task);
		}
		if (pre_entry)
			p->ss_addr = (void *)pre_entry (jp->priv_arg, regs);
		if (entry){
			entry (regs->ARM_r0, regs->ARM_r1, regs->ARM_r2, regs->ARM_r3, regs->ARM_r4, regs->ARM_r5);
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
EXPORT_SYMBOL_GPL(setjmp_pre_handler);

void dbi_jprobe_return (void)
{
}

void dbi_arch_uprobe_return (void)
{
}
EXPORT_SYMBOL_GPL(dbi_arch_uprobe_return);

int longjmp_break_handler (struct kprobe *p, struct pt_regs *regs)
{
# ifndef REENTER
	//kprobe_opcode_t insn = BREAKPOINT_INSTRUCTION;
	kprobe_opcode_t insns[2];

	if (p->pid)
	{
		insns[0] = BREAKPOINT_INSTRUCTION;
		insns[1] = p->opcode;
		//p->opcode = *p->addr;
		if (read_proc_vm_atomic (current, (unsigned long) (p->addr), &(p->opcode), sizeof (p->opcode)) < sizeof (p->opcode))
		{
			printk ("ERROR[%lu]: failed to read vm of proc %s/%u addr %p.", nCount, current->comm, current->pid, p->addr);
			return -1;
		}
		//*p->addr = BREAKPOINT_INSTRUCTION;
		//*(p->addr+1) = p->opcode;
		if (write_proc_vm_atomic (current, (unsigned long) (p->addr), insns, sizeof (insns)) < sizeof (insns))
		{
			printk ("ERROR[%lu]: failed to write vm of proc %s/%u addr %p.", nCount, current->comm, current->pid, p->addr);
			return -1;
		}
	}
	else
	{
		DBPRINTF ("p->opcode = 0x%lx *p->addr = 0x%lx p->addr = 0x%p\n", p->opcode, *p->addr, p->addr);
		*(p->addr + 1) = p->opcode;
		p->opcode = *p->addr;
		*p->addr = BREAKPOINT_INSTRUCTION;

		flush_icache_range ((unsigned int) p->addr, (unsigned int) (((unsigned int) p->addr) + (sizeof (kprobe_opcode_t) * 2)));
	}

	reset_current_kprobe();

#endif //REENTER

	return 0;
}
EXPORT_SYMBOL_GPL(longjmp_break_handler);

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
	struct hlist_head *head;
	struct hlist_node *node, *tmp;
	unsigned long flags, orig_ret_address = 0;
	unsigned long trampoline_address = (unsigned long) &kretprobe_trampoline;

	struct kretprobe *crp = NULL;
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	DBPRINTF ("start");

	if (p && p->tgid){
		// in case of user space retprobe trampoline is at the Nth instruction of US tramp
		if (!thumb_mode( regs ))
			trampoline_address = (unsigned long)(p->ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
		else
			trampoline_address = (unsigned long)(p->ainsn.insn) + 0x1b;
	}

	spin_lock_irqsave (&kretprobe_lock, flags);

	/*
	 * We are using different hash keys (current and mm) for finding kernel
	 * space and user space probes.  Kernel space probes can change mm field in
	 * task_struct.  User space probes can be shared between threads of one
	 * process so they have different current but same mm.
	 */
	if (p && p->tgid) {
		head = kretprobe_inst_table_head(current->mm);
	} else {
		head = kretprobe_inst_table_head(current);
	}

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
	//E.G. Check this code in case of __switch_to function instrumentation -- currently this code generates dump in this case
	//if (trampoline_address != (unsigned long) &kretprobe_trampoline){
	//if (ri->rp2) BUG_ON (ri->rp2->kp.tgid == 0);
	//if (ri->rp) BUG_ON (ri->rp->kp.tgid == 0);
	//else if (ri->rp2) BUG_ON (ri->rp2->kp.tgid == 0);
	//}
	if ((ri->rp && ri->rp->kp.tgid) || (ri->rp2 && ri->rp2->kp.tgid))
		BUG_ON (trampoline_address == (unsigned long) &kretprobe_trampoline);

	regs->uregs[14] = orig_ret_address;
	DBPRINTF ("regs->uregs[14] = 0x%lx\n", regs->uregs[14]);
	DBPRINTF ("regs->uregs[15] = 0x%lx\n", regs->uregs[15]);

	if (trampoline_address != (unsigned long) &kretprobe_trampoline)
	{
		regs->uregs[15] = orig_ret_address;
	}else{
		if (!thumb_mode( regs )) regs->uregs[15] += 4;
		else regs->uregs[15] += 2;
	}

	DBPRINTF ("regs->uregs[15] = 0x%lx\n", regs->uregs[15]);

	if(p){ // ARM, MIPS, X86 user space
		if (thumb_mode( regs ) && !(regs->uregs[14] & 0x01))
		{
			regs->ARM_cpsr &= 0xFFFFFFDF;
		}else{
			if (user_mode( regs ) && (regs->uregs[14] & 0x01))
			{
				regs->ARM_cpsr |= 0x20;
			}
		}

		//TODO: test - enter function, delete us retprobe, exit function
		// for user space retprobes only - deferred deletion

		if (trampoline_address != (unsigned long) &kretprobe_trampoline)
		{
			// if we are not at the end of the list and current retprobe should be disarmed
			if (node && ri->rp2)
			{
				struct hlist_node *current_node = node;
				crp = ri->rp2;
				/*sprintf(die_msg, "deferred disarm p->addr = %p [%lx %lx %lx]\n",
				  crp->kp.addr, *kaddrs[0], *kaddrs[1], *kaddrs[2]);
				  DIE(die_msg, regs); */
				// look for other instances for the same retprobe
				hlist_for_each_entry_safe (ri, node, tmp, head, hlist)
				{
					/*
					 * Trying to find another retprobe instance associated with
					 * the same retprobe.
					 */
					if (ri->rp2 == crp && node != current_node)
						break;
				}

				if (!node)
				{
					// if there are no more instances for this retprobe
					// delete retprobe
					struct kprobe *is_p = &crp->kp;
					DBPRINTF ("defered retprobe deletion p->addr = %p", crp->kp.addr);
					/*
					  If there is no any retprobe instances of this retprobe
					  we can free the resources related to the probe.
					 */
					if (!(hlist_unhashed(&is_p->is_hlist_arm))) {
						hlist_del_rcu(&is_p->is_hlist_arm);
					}
					if (!(hlist_unhashed(&is_p->is_hlist_thumb))) {
						hlist_del_rcu(&is_p->is_hlist_thumb);
					}

					dbi_unregister_kprobe(&crp->kp, current);
					kfree (crp);
				}
				hlist_del(current_node);
			}
		}

		if (kcb->kprobe_status == KPROBE_REENTER) {
			restore_previous_kprobe(kcb);
		} else {
			reset_current_kprobe();
		}
	}

	spin_unlock_irqrestore (&kretprobe_lock, flags);

	/*
	 * By returning a non-zero value, we are telling
	 * kprobe_handler() that we don't want the post_handler
	 * to run (and have re-enabled preemption)
	 */

	return 1;
}
EXPORT_SYMBOL_GPL(trampoline_probe_handler);

void  __arch_prepare_kretprobe (struct kretprobe *rp, struct pt_regs *regs)
{
	struct kretprobe_instance *ri;

	DBPRINTF ("start\n");
	//TODO: test - remove retprobe after func entry but before its exit
	if ((ri = get_free_rp_inst (rp)) != NULL)
	{
		ri->rp = rp;
		ri->rp2 = NULL;
		ri->task = current;
		ri->ret_addr = (kprobe_opcode_t *) regs->uregs[14];
		ri->sp = (kprobe_opcode_t *)regs->ARM_sp; //uregs[13];

		if (rp->kp.tgid)
			if (!thumb_mode( regs ))
				regs->uregs[14] = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
			else
				regs->uregs[14] = (unsigned long) (rp->kp.ainsn.insn) + 0x1b;

		else	/* Replace the return addr with trampoline addr */
			regs->uregs[14] = (unsigned long) &kretprobe_trampoline;

//		DBPRINTF ("ret addr set to %p->%lx\n", ri->ret_addr, regs->uregs[14]);
		add_rp_inst (ri);
	}
	else {
		DBPRINTF ("WARNING: missed retprobe %p\n", rp->kp.addr);
		rp->nmissed++;
	}
}


int asm_init_module_dependencies(void)
{
	//No module dependencies
	return 0;
}

void swap_register_undef_hook(struct undef_hook *hook)
{
	__swap_register_undef_hook(hook);
}
EXPORT_SYMBOL_GPL(swap_register_undef_hook);

void swap_unregister_undef_hook(struct undef_hook *hook)
{
	__swap_unregister_undef_hook(hook);
}
EXPORT_SYMBOL_GPL(swap_unregister_undef_hook);

// kernel probes hook
static struct undef_hook undef_ho_k = {
    .instr_mask	= 0xffffffff,
    .instr_val	= BREAKPOINT_INSTRUCTION,
    .cpsr_mask	= MODE_MASK,
    .cpsr_val	= SVC_MODE,
    .fn		= kprobe_trap_handler
};

int __init arch_init_kprobes (void)
{
	unsigned int do_bp_handler = 0;
	int ret = 0;

	if (arch_init_module_dependencies())
	{
		DBPRINTF ("Unable to init module dependencies\n");
		return -1;
	}

	do_bp_handler = swap_ksyms("do_undefinstr");
	if (do_bp_handler == 0) {
		DBPRINTF("no do_undefinstr symbol found!");
                return -1;
        }
	arr_traps_template[NOTIFIER_CALL_CHAIN_INDEX] = arch_construct_brunch ((unsigned int)kprobe_handler, do_bp_handler + NOTIFIER_CALL_CHAIN_INDEX * 4, 1);
	// Register hooks (kprobe_handler)
	__swap_register_undef_hook = swap_ksyms("register_undef_hook");
	if (__swap_register_undef_hook == NULL) {
		printk("no register_undef_hook symbol found!\n");
                return -1;
        }

        // Unregister hooks (kprobe_handler)
	__swap_unregister_undef_hook = swap_ksyms("unregister_undef_hook");
	if (__swap_unregister_undef_hook == NULL) {
                printk("no unregister_undef_hook symbol found!\n");
                return -1;
        }

	swap_register_undef_hook(&undef_ho_k);
	if ((ret = dbi_register_kprobe (&trampoline_p)) != 0) {
		//dbi_unregister_jprobe(&do_exit_p, 0);
		return ret;
	}
	return ret;
}

void __exit dbi_arch_exit_kprobes (void)
{
	swap_unregister_undef_hook(&undef_ho_k);
}

//EXPORT_SYMBOL_GPL (dbi_arch_uprobe_return);
//EXPORT_SYMBOL_GPL (dbi_arch_exit_kprobes);
