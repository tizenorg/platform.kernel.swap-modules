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
 *

 */

#include<linux/module.h>

#include "dbi_kprobes.h"
#include "../dbi_kprobes.h"


#include "../../dbi_kdebug.h"
#include "../../dbi_insn_slots.h"
#include "../../dbi_kprobes_deps.h"
#include "../../dbi_uprobes.h"

#include <asm/cacheflush.h>

unsigned int *arr_traps_original;

extern unsigned int *sched_addr;
extern unsigned int *fork_addr;

extern struct kprobe * per_cpu__current_kprobe;
extern spinlock_t kretprobe_lock;
extern struct kretprobe *sched_rp;

extern struct hlist_head kprobe_insn_pages;
extern struct hlist_head uprobe_insn_pages;

extern unsigned long (*kallsyms_search) (const char *name);

extern struct kprobe *kprobe_running (void);
extern struct kprobe_ctlblk *get_kprobe_ctlblk (void);
extern void reset_current_kprobe (void);

unsigned int arr_traps_template[] = {   0xe1a0c00d,    // mov          ip, sp
	0xe92dd800,    // stmdb        sp!, {fp, ip, lr, pc}
	     0xe24cb004,    // sub          fp, ip, #4      ; 0x4
	     0x00000000,    // b                                    
	     0xe3500000,    // cmp          r0, #0  ; 0x0   
	     0xe89da800,    // ldmia        sp, {fp, sp, pc}
	     0x00000000,    // nop
	     0xffffffff     // end
};


/*
 * Function return probe trampoline:
 * 	- init_kprobes() establishes a probepoint here
 * 	- When the probed function returns, this probe
 * 		causes the handlers to fire
 */
void kretprobe_trampoline_holder (void)
{
	asm volatile (".global kretprobe_trampoline\n"
			"kretprobe_trampoline:\n"
			"nop\n"
			"nop\n" 
			"mov pc, r14\n");
}


struct kprobe trampoline_p =
{
	.addr = (kprobe_opcode_t *) & kretprobe_trampoline,
	.pre_handler = trampoline_probe_handler
};


void gen_insn_execbuf_holder (void)
{
	asm volatile (".global gen_insn_execbuf\n" 
			"gen_insn_execbuf:\n" 
			"nop\n" 
			"nop\n" 
			"nop\n"	                // original instruction
			"nop\n" 
			"ldr	pc, [pc, #4]\n" //ssbreak 
			"nop\n"                   //retbreak
			"nop\n" 
			"nop\n");                 //stored PC-4(next insn addr)
}


/*
 * 0. push Rx on stack
 * 1. load address to Rx
 * 2. do insn using Rx
 * 3. pop Rx from stack
 * 4. BREAK1
 * 5. BREAK2
 * 6. stored PC
 * 7. stored PC-4(next insn addr)
 */
void pc_dep_insn_execbuf_holder (void)
{
	asm volatile (".global pc_dep_insn_execbuf\n" 
			"pc_dep_insn_execbuf:\n"
			"str	r0, [sp, #-4]\n" 
			"ldr	r0, [pc, #12]\n" 
			"nop\n"	// instruction with replaced PC
			"ldr	r0, [sp, #-4]\n"
			"ldr	pc, [pc, #4]\n" //ssbreak
			"nop\n"	// retbreak
			"nop\n" // stored PC
			"nop\n");// stored PC-4 (next insn addr)
}

int prep_pc_dep_insn_execbuf (kprobe_opcode_t * insns, kprobe_opcode_t insn, int uregs)
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
			//              DBPRINTF("prep_pc_dep_insn_execbuf: check R%d/%d, changing regs %x in %x", 
			//                              i, ARM_INSN_REG_RN(insn), uregs, insn);
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


int arch_check_insn (struct arch_specific_insn *ainsn)
{
	int ret = 0;
	// check instructions that can change PC by nature 
	if (ARM_INSN_MATCH (UNDEF, ainsn->insn[0]) ||
			ARM_INSN_MATCH (AUNDEF, ainsn->insn[0]) ||
			ARM_INSN_MATCH (SWI, ainsn->insn[0]) ||
			ARM_INSN_MATCH (BREAK, ainsn->insn[0]) ||
			ARM_INSN_MATCH (B, ainsn->insn[0]) ||
			ARM_INSN_MATCH (BL, ainsn->insn[0]) ||
			ARM_INSN_MATCH (BLX1, ainsn->insn[0]) || 
			ARM_INSN_MATCH (BLX2, ainsn->insn[0]) || 
			ARM_INSN_MATCH (BX, ainsn->insn[0]) || 
			ARM_INSN_MATCH (BXJ, ainsn->insn[0]))
	{
		DBPRINTF ("arch_check_insn: %lx\n", ainsn->insn[0]);
		ret = -EFAULT;
	}
#ifndef CONFIG_CPU_V7
	// check instructions that can write result to PC
	else if ((ARM_INSN_MATCH (DPIS, ainsn->insn[0]) ||
				ARM_INSN_MATCH (DPRS, ainsn->insn[0]) ||
				ARM_INSN_MATCH (DPI, ainsn->insn[0]) || 
				ARM_INSN_MATCH (LIO, ainsn->insn[0]) || 
				ARM_INSN_MATCH (LRO, ainsn->insn[0])) && 
			(ARM_INSN_REG_RD (ainsn->insn[0]) == 15))
	{
		DBPRINTF ("arch_check_insn: %lx\n", ainsn->insn[0]);
		ret = -EFAULT;
	}
#endif // CONFIG_CPU_V7
	// check special instruction loads store multiple registers
	else if ((ARM_INSN_MATCH (LM, ainsn->insn[0]) || ARM_INSN_MATCH (SM, ainsn->insn[0])) &&
			// store pc or load to pc
			(ARM_INSN_REG_MR (ainsn->insn[0], 15) ||
			 // store/load with pc update
			 ((ARM_INSN_REG_RN (ainsn->insn[0]) == 15) && (ainsn->insn[0] & 0x200000))))
	{
		DBPRINTF ("arch_check_insn: %lx\n", ainsn->insn[0]);
		ret = -EFAULT;
	}
	return ret;
}

int arch_prepare_kretprobe (struct kretprobe *p)
{
	DBPRINTF("Warrning: arch_prepare_kretprobe is not implemented\n");
	return 0;
}

int arch_prepare_kprobe (struct kprobe *p)
{
	kprobe_opcode_t insns[KPROBES_TRAMP_LEN];
	int uregs, pc_dep;
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

			p->ainsn.boostable = 1;
			uregs = pc_dep = 0;
			// Rn, Rm ,Rd
			if (ARM_INSN_MATCH (DPIS, insn[0]) || ARM_INSN_MATCH (LRO, insn[0]) || 
					ARM_INSN_MATCH (SRO, insn[0]))
			{

				uregs = 0xb;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) || 
						(ARM_INSN_MATCH (SRO, insn[0]) && (ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					DBPRINTF ("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
					pc_dep = 1;
				}
			}
			// Rn ,Rd
			else if (ARM_INSN_MATCH (DPI, insn[0]) || ARM_INSN_MATCH (LIO, insn[0]) || 
					ARM_INSN_MATCH (SIO, insn[0]))
			{

				uregs = 0x3;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_MATCH (SIO, insn[0]) && 
							(ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					pc_dep = 1;
					DBPRINTF ("Unboostable insn %lx/%p/%d, DPI/LIO/SIO\n", insn[0], p, p->ainsn.boostable);
				}
			}
			// Rn, Rm, Rs                                   
			else if (ARM_INSN_MATCH (DPRS, insn[0]))
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
			else if (ARM_INSN_MATCH (SM, insn[0]))
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
				static int count;
				count++;
				//printk ("insn writes result to SP and uses PC: %lx/%d\n", ainsn.insn[0], count);
				free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, 0);
				ret = -EFAULT;
			}
			else {
				if (uregs && pc_dep)
				{
					memcpy (insns, pc_dep_insn_execbuf, sizeof (insns));
					if (prep_pc_dep_insn_execbuf (insns, insn[0], uregs) != 0)
					{
						DBPRINTF ("failed to prepare exec buffer for insn %lx!", insn[0]);
						free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, 0);
						return -EINVAL;
					}
					//insns[KPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
					insns[6] = (kprobe_opcode_t) (p->addr + 2);
				}
				else
				{
					memcpy (insns, gen_insn_execbuf, sizeof (insns));
					insns[KPROBES_TRAMP_INSN_IDX] = insn[0];
				}			
				//insns[KPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
				insns[7] = (kprobe_opcode_t) (p->addr + 1);
				DBPRINTF ("arch_prepare_kprobe: insn %lx", insn[0]);
				DBPRINTF ("arch_prepare_kprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx", 
						p->ainsn.insn, insns[0], insns[1], insns[2], insns[3], insns[4], 
						insns[5], insns[6], insns[7], insns[8]);
				memcpy (p->ainsn.insn, insns, sizeof(insns));
			}
		}
		else
		{
			free_insn_slot (&kprobe_insn_pages, NULL, p->ainsn.insn, 0);
		}
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

int arch_prepare_uprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	int ret = 0;
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN];

	int uregs, pc_dep;

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

			p->ainsn.boostable = 1;
			uregs = pc_dep = 0;
			// Rn, Rm ,Rd
			if (ARM_INSN_MATCH (DPIS, insn[0]) || ARM_INSN_MATCH (LRO, insn[0]) || 
					ARM_INSN_MATCH (SRO, insn[0]))
			{

				uregs = 0xb;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_REG_RM (insn[0]) == 15) || 
						(ARM_INSN_MATCH (SRO, insn[0]) && (ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					DBPRINTF ("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
					pc_dep = 1;
				}
			}
			// Rn ,Rd
			else if (ARM_INSN_MATCH (DPI, insn[0]) || ARM_INSN_MATCH (LIO, insn[0]) || 
					ARM_INSN_MATCH (SIO, insn[0]))
			{

				uregs = 0x3;
				if ((ARM_INSN_REG_RN (insn[0]) == 15) || (ARM_INSN_MATCH (SIO, insn[0]) && 
							(ARM_INSN_REG_RD (insn[0]) == 15)))
				{

					pc_dep = 1;
					DBPRINTF ("Unboostable insn %lx/%p/%d, DPI/LIO/SIO\n", insn[0], p, p->ainsn.boostable);
				}
			}
			// Rn, Rm, Rs                                   
			else if (ARM_INSN_MATCH (DPRS, insn[0]))
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
			else if (ARM_INSN_MATCH (SM, insn[0]))
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
				static int count;
				count++;
				//printk ("insn writes result to SP and uses PC: %lx/%d\n", ainsn.insn[0], count);
				free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, 0);
				ret = -EFAULT;
			}
			else {
				if (uregs && pc_dep)
				{
					memcpy (insns, pc_dep_insn_execbuf, sizeof (insns));
					if (prep_pc_dep_insn_execbuf (insns, insn[0], uregs) != 0)
					{
						DBPRINTF ("failed to prepare exec buffer for insn %lx!", insn[0]);
						free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, 0);
						return -EINVAL;
					}
					//insns[UPROBES_TRAMP_SS_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
					insns[6] = (kprobe_opcode_t) (p->addr + 2);
				}
				else
				{
					memcpy (insns, gen_insn_execbuf, sizeof (insns));
					insns[UPROBES_TRAMP_INSN_IDX] = insn[0];
				}			
				insns[UPROBES_TRAMP_RET_BREAK_IDX] = UNDEF_INSTRUCTION;
				insns[7] = (kprobe_opcode_t) (p->addr + 1);
				DBPRINTF ("arch_prepare_uprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx", 
						p->ainsn.insn, insns[0], insns[1], insns[2], insns[3], insns[4], 
						insns[5], insns[6], insns[7], insns[8]);
			}

			if (!write_proc_vm_atomic (task, (unsigned long) p->ainsn.insn, insns, sizeof (insns)))
			{
				panic("failed to write memory %p!\n", p->ainsn.insn);
				DBPRINTF ("failed to write insn slot to process memory: insn %p, addr %p, probe %p!", insn, p->ainsn.insn, p->addr);
				/*printk ("failed to write insn slot to process memory: %p/%d insn %lx, addr %p, probe %p!\n", 
				  task, task->pid, insn, p->ainsn.insn, p->addr);*/
				free_insn_slot (&uprobe_insn_pages, task, p->ainsn.insn, 0);
				return -EINVAL;
			}
		}
	}

	return ret;

}

int arch_prepare_uretprobe (struct kretprobe *p, struct task_struct *task)
{
	DBPRINTF("Warrning: arch_prepare_uretprobe is not implemented\n");
	return 0;
}

void prepare_singlestep (struct kprobe *p, struct pt_regs *regs)
{
	if(p->ss_addr)
	{
		regs->uregs[15] = (unsigned long) p->ss_addr;
		p->ss_addr = NULL;
	}
	else
		regs->uregs[15] = (unsigned long) p->ainsn.insn;
}

void save_previous_kprobe (struct kprobe_ctlblk *kcb, struct kprobe *cur_p)
{
	if (kcb->prev_kprobe.kp != NULL)
	{
		DBPRINTF ("no space to save new probe[]: task = %d/%s", current->pid, current->comm);
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
	DBPRINTF ("set_current_kprobe: p=%p addr=%p\n", p, p->addr);
}


int kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *p = 0;
	int ret = 0, pid = 0, retprobe = 0, reenter = 0;
	kprobe_opcode_t *addr = NULL, *ssaddr = 0;
	struct kprobe_ctlblk *kcb;

	/* We're in an interrupt, but this is clear and BUG()-safe. */

	addr = (kprobe_opcode_t *) (regs->uregs[15] - 4);
	DBPRINTF ("KPROBE: regs->uregs[15] = 0x%lx addr = 0x%p\n", regs->uregs[15], addr);
	regs->uregs[15] -= 4;
	//DBPRINTF("regs->uregs[14] = 0x%lx\n", regs->uregs[14]);

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
		p = get_kprobe (addr, pid, current);
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
					regs->uregs[15] = (unsigned long) (p->addr + 1);
					DBPRINTF ("finish step at %p cur at %p/%p, redirect to %lx\n", addr, p->addr, p->ainsn.insn, regs->uregs[15]);
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
		p = get_kprobe (addr, pid, current);
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
		else if(p->pre_handler != trampoline_probe_handler)
			reset_current_kprobe ();			
	}

	if (ret)
	{
		DBPRINTF ("p->pre_handler 1");
		/* handler has already set things up, so skip ss setup */
		return 1;
	}
	DBPRINTF ("p->pre_handler 0");

no_kprobe:
	preempt_enable_no_resched ();
	return ret;
}


void patch_suspended_task_ret_addr(struct task_struct *p, struct kretprobe *rp)
{
	struct kretprobe_instance *ri = NULL;
	struct hlist_node *node, *tmp; 
	struct hlist_head *head;
	unsigned long flags;
	int found = 0;

	spin_lock_irqsave (&kretprobe_lock, flags); 
	head = kretprobe_inst_table_head (p);
	hlist_for_each_entry_safe (ri, node, tmp, head, hlist){
		if ((ri->rp == rp) && (p == ri->task)){
			found = 1;
			break; 
		}
	}
	spin_unlock_irqrestore (&kretprobe_lock, flags); 

#ifndef task_thread_info
#define task_thread_info(task) (task)->thread_info
#endif // task_thread_info

	if (found){
		// update PC
		if(thread_saved_pc(p) != (unsigned long)&kretprobe_trampoline){
			ri->ret_addr = (kprobe_opcode_t *)thread_saved_pc(p);
			task_thread_info(p)->cpu_context.pc = (unsigned long) &kretprobe_trampoline;
		}
		return; 
	}

	if ((ri = get_free_rp_inst(rp)) != NULL)
	{
		ri->rp = rp; 
		ri->rp2 = NULL; 
		ri->task = p;
		ri->ret_addr = (kprobe_opcode_t *)thread_saved_pc(p);
		task_thread_info(p)->cpu_context.pc = (unsigned long) &kretprobe_trampoline;
		add_rp_inst (ri);
		//		printk("change2 saved pc %p->%p for %d/%d/%p\n", ri->ret_addr, &kretprobe_trampoline, p->tgid, p->pid, p);
	}
	else{
		printk("no ri for %d\n", p->pid);
		BUG();				
	}
}

int setjmp_pre_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of (p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry;
	entry_point_t entry;

# ifdef REENTER
	p = __get_cpu_var (current_kprobe);
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
		if(!p->tgid && ((unsigned int)p->addr == sched_addr) && sched_rp){
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
			entry (regs->ARM_r0, regs->ARM_r1, regs->ARM_r2, regs->ARM_r3, regs->ARM_r4, regs->ARM_r5);
		}
		else {
			if (p->tgid)
				arch_uprobe_return ();
			else
				jprobe_return ();
		}
	}
	else if (p->tgid)
		arch_uprobe_return ();

	prepare_singlestep (p, regs);

	return 1;	
}

void jprobe_return (void)
{
	preempt_enable_no_resched();
}

void arch_uprobe_return (void)
{
	preempt_enable_no_resched();
}

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

	reset_current_kprobe ();

#endif //REENTER 

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
		recycle_rp_inst (ri, &empty_rp); 
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
		regs->uregs[15] = orig_ret_address;
	else
		regs->uregs[15] += 4;
	DBPRINTF ("regs->uregs[15] = 0x%lx\n", regs->uregs[15]);

	if(p){ // ARM, MIPS, X86 user space
		if (kcb->kprobe_status == KPROBE_REENTER)
			restore_previous_kprobe (kcb);
		else
			reset_current_kprobe ();

		//TODO: test - enter function, delete us retprobe, exit function 
		// for user space retprobes only - deferred deletion
		if (trampoline_address != (unsigned long) &kretprobe_trampoline)
		{
			// if we are not at the end of the list and current retprobe should be disarmed 
			if (node && ri->rp2)
			{
				crp = ri->rp2;
				/*sprintf(die_msg, "deferred disarm p->addr = %p [%lx %lx %lx]\n", 
				  crp->kp.addr, *kaddrs[0], *kaddrs[1], *kaddrs[2]);
				  DIE(die_msg, regs); */
				// look for other instances for the same retprobe
				hlist_for_each_entry_continue (ri, node, hlist)
				{
					if (ri->task != current) 
						continue;	/* another task is sharing our hash bucket */
					if (ri->rp2 == crp)	//if instance belong to the same retprobe
						break;
				}
				if (!node)
				{	// if there are no more instances for this retprobe
					// delete retprobe
					DBPRINTF ("defered retprobe deletion p->addr = %p", crp->kp.addr);
					unregister_uprobe (&crp->kp, current, 1);
					kfree (crp);
				}
			}
		}
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
		if (rp->kp.tgid)
			regs->uregs[14] = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
		else	/* Replace the return addr with trampoline addr */
			regs->uregs[14] = (unsigned long) &kretprobe_trampoline; 
		DBPRINTF ("ret addr set to %p->%lx\n", ri->ret_addr, regs->uregs[14]);
		add_rp_inst (ri);
	}
	else {
		DBPRINTF ("WARNING: missed retprobe %p\n", rp->kp.addr);
		rp->nmissed++;
	}

}

int asm_init_module_dependencies()
{
	//No module dependencies 
	return 0;
}

int __init arch_init_kprobes (void)
{

	unsigned int do_bp_handler; 
	unsigned int kprobe_handler_addr;

	unsigned int insns_num = 0;
	unsigned int code_size = 0;

	int ret = 0;

	if (arch_init_module_dependencies())
	{
		DBPRINTF ("Unable to init module dependencies\n"); 
		return -1;
	}

	do_bp_handler = (unsigned int) kallsyms_search ("do_undefinstr");

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

	arr_traps_template[NOTIFIER_CALL_CHAIN_INDEX] = arch_construct_brunch ((unsigned int)kprobe_handler, do_bp_handler + NOTIFIER_CALL_CHAIN_INDEX * 4, 1);

	// Insert new code
	memcpy ((void *) do_bp_handler, arr_traps_template, code_size); 
	flush_icache_range (do_bp_handler, do_bp_handler + code_size); 
	if((ret = register_kprobe (&trampoline_p, 0)) != 0){
		//unregister_jprobe(&do_exit_p, 0);
		return ret;
	}

	return ret;	
}

void __exit arch_exit_kprobes (void)
{
	unsigned int do_bp_handler;

	unsigned int insns_num = 0;
	unsigned int code_size = 0;

	// Get instruction address  
	do_bp_handler = (unsigned int) kallsyms_search ("do_undefinstr");

	//unregister_jprobe(&do_exit_p, 0);

	// Replace back the original code

	insns_num = sizeof (arr_traps_template) / sizeof (arr_traps_template[0]);
	code_size = insns_num * sizeof (unsigned int); 
	memcpy ((void *) do_bp_handler, arr_traps_original, code_size); 
	flush_icache_range (do_bp_handler, do_bp_handler + code_size); 
	kfree (arr_traps_original); 
	arr_traps_original = NULL;
}


EXPORT_SYMBOL_GPL (arch_uprobe_return);
EXPORT_SYMBOL_GPL (arch_exit_kprobes);

