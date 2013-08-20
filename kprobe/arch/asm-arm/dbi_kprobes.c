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
#include "trampoline_arm.h"
#include "../dbi_kprobes.h"
#include "../../dbi_kprobes.h"

#include "../../dbi_kdebug.h"
#include "../../dbi_insn_slots.h"
#include "../../dbi_kprobes_deps.h"
#include <ksyms.h>

#include <asm/cacheflush.h>
#include <asm/traps.h>
#include <asm/ptrace.h>
#include <linux/list.h>
#include <linux/hash.h>

#define SUPRESS_BUG_MESSAGES

extern struct kprobe * per_cpu__current_kprobe;
extern struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];

static void (*__swap_register_undef_hook)(struct undef_hook *hook);
static void (*__swap_unregister_undef_hook)(struct undef_hook *hook);

int prep_pc_dep_insn_execbuf(kprobe_opcode_t *insns, kprobe_opcode_t insn, int uregs)
{
	int i;

	if (uregs & 0x10) {
		int reg_mask = 0x1;
		//search in reg list
		for (i = 0; i < 13; i++, reg_mask <<= 1) {
			if (!(insn & reg_mask))
				break;
		}
	} else {
		for (i = 0; i < 13; i++) {
			if ((uregs & 0x1) && (ARM_INSN_REG_RN(insn) == i))
				continue;
			if ((uregs & 0x2) && (ARM_INSN_REG_RD(insn) == i))
				continue;
			if ((uregs & 0x4) && (ARM_INSN_REG_RS(insn) == i))
				continue;
			if ((uregs & 0x8) && (ARM_INSN_REG_RM(insn) == i))
				continue;
			break;
		}
	}

	if (i == 13) {
		DBPRINTF ("there are no free register %x in insn %lx!", uregs, insn);
		return -EINVAL;
	}
	DBPRINTF ("prep_pc_dep_insn_execbuf: using R%d, changing regs %x", i, uregs);

	// set register to save
	ARM_INSN_REG_SET_RD(insns[0], i);
	// set register to load address to
	ARM_INSN_REG_SET_RD(insns[1], i);
	// set instruction to execute and patch it
	if (uregs & 0x10) {
		ARM_INSN_REG_CLEAR_MR(insn, 15);
		ARM_INSN_REG_SET_MR(insn, i);
	} else {
		if ((uregs & 0x1) && (ARM_INSN_REG_RN(insn) == 15))
			ARM_INSN_REG_SET_RN(insn, i);
		if ((uregs & 0x2) && (ARM_INSN_REG_RD(insn) == 15))
			ARM_INSN_REG_SET_RD(insn, i);
		if ((uregs & 0x4) && (ARM_INSN_REG_RS(insn) == 15))
			ARM_INSN_REG_SET_RS(insn, i);
		if ((uregs & 0x8) && (ARM_INSN_REG_RM(insn) == 15))
			ARM_INSN_REG_SET_RM(insn, i);
	}

	insns[UPROBES_TRAMP_INSN_IDX] = insn;
	// set register to restore
	ARM_INSN_REG_SET_RD(insns[3], i);

	return 0;
}
EXPORT_SYMBOL_GPL(prep_pc_dep_insn_execbuf);

int arch_check_insn_arm(struct arch_specific_insn *ainsn)
{
	int ret = 0;

	// check instructions that can change PC by nature
	if (
//	    ARM_INSN_MATCH(UNDEF, ainsn->insn_arm[0]) ||
	    ARM_INSN_MATCH(AUNDEF, ainsn->insn_arm[0]) ||
	    ARM_INSN_MATCH(SWI, ainsn->insn_arm[0]) ||
	    ARM_INSN_MATCH(BREAK, ainsn->insn_arm[0]) ||
	    ARM_INSN_MATCH(BXJ, ainsn->insn_arm[0])) 	{
		DBPRINTF ("Bad insn arch_check_insn_arm: %lx\n", ainsn->insn_arm[0]);
		ret = -EFAULT;
#ifndef CONFIG_CPU_V7
	// check instructions that can write result to PC
	} else if ((ARM_INSN_MATCH(DPIS, ainsn->insn_arm[0]) ||
		   ARM_INSN_MATCH(DPRS, ainsn->insn_arm[0]) ||
		   ARM_INSN_MATCH(DPI, ainsn->insn_arm[0]) ||
		   ARM_INSN_MATCH(LIO, ainsn->insn_arm[0]) ||
		   ARM_INSN_MATCH(LRO, ainsn->insn_arm[0])) &&
		   (ARM_INSN_REG_RD(ainsn->insn_arm[0]) == 15)) {
		DBPRINTF ("Bad arch_check_insn_arm: %lx\n", ainsn->insn_arm[0]);
		ret = -EFAULT;
#endif // CONFIG_CPU_V7
	// check special instruction loads store multiple registers
	} else if ((ARM_INSN_MATCH(LM, ainsn->insn_arm[0]) || ARM_INSN_MATCH(SM, ainsn->insn_arm[0])) &&
			// store pc or load to pc
		   (ARM_INSN_REG_MR(ainsn->insn_arm[0], 15) ||
			 // store/load with pc update
		    ((ARM_INSN_REG_RN(ainsn->insn_arm[0]) == 15) && (ainsn->insn_arm[0] & 0x200000)))) {
		DBPRINTF ("Bad insn arch_check_insn_arm: %lx\n", ainsn->insn_arm[0]);
		ret = -EFAULT;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(arch_check_insn_arm);

int arch_prepare_kprobe(struct kprobe *p, struct slot_manager *sm)
{
	kprobe_opcode_t insns[KPROBES_TRAMP_LEN];
	int uregs, pc_dep, ret = 0;
	kprobe_opcode_t insn[MAX_INSN_SIZE];
	struct arch_specific_insn ainsn;

	/* insn: must be on special executable page on i386. */
	p->ainsn.insn = alloc_insn_slot(sm);
	if (!p->ainsn.insn)
		return -ENOMEM;

	memcpy(insn, p->addr, MAX_INSN_SIZE * sizeof(kprobe_opcode_t));
	ainsn.insn_arm = ainsn.insn = insn;
	ret = arch_check_insn_arm(&ainsn);
	if (!ret) {
		p->opcode = *p->addr;
		uregs = pc_dep = 0;

		// Rn, Rm ,Rd
		if (ARM_INSN_MATCH(DPIS, insn[0]) || ARM_INSN_MATCH(LRO, insn[0]) ||
		    ARM_INSN_MATCH(SRO, insn[0])) {
			uregs = 0xb;
			if ((ARM_INSN_REG_RN(insn[0]) == 15) || (ARM_INSN_REG_RM(insn[0]) == 15) ||
			    (ARM_INSN_MATCH(SRO, insn[0]) && (ARM_INSN_REG_RD(insn[0]) == 15))) {
				DBPRINTF ("Unboostable insn %lx, DPIS/LRO/SRO\n", insn[0]);
				pc_dep = 1;
			}

		// Rn ,Rd
		} else if( ARM_INSN_MATCH(DPI, insn[0]) || ARM_INSN_MATCH(LIO, insn[0]) ||
			   ARM_INSN_MATCH(SIO, insn[0])) {
			uregs = 0x3;
			if ((ARM_INSN_REG_RN(insn[0]) == 15) || (ARM_INSN_MATCH(SIO, insn[0]) &&
			    (ARM_INSN_REG_RD (insn[0]) == 15))) {
				pc_dep = 1;
				DBPRINTF ("Unboostable insn %lx/%p, DPI/LIO/SIO\n", insn[0], p);
			}
		// Rn, Rm, Rs
		} else if (ARM_INSN_MATCH(DPRS, insn[0])) {
			uregs = 0xd;
			if ((ARM_INSN_REG_RN(insn[0]) == 15) || (ARM_INSN_REG_RM(insn[0]) == 15) ||
			    (ARM_INSN_REG_RS (insn[0]) == 15)) {
				pc_dep = 1;
				DBPRINTF ("Unboostable insn %lx, DPRS\n", insn[0]);
			}
		// register list
		} else if(ARM_INSN_MATCH(SM, insn[0])) {
			uregs = 0x10;
			if (ARM_INSN_REG_MR(insn[0], 15)) {
				DBPRINTF ("Unboostable insn %lx, SM\n", insn[0]);
				pc_dep = 1;
			}
		}

		// check instructions that can write result to SP andu uses PC
		if (pc_dep  && (ARM_INSN_REG_RD(ainsn.insn[0]) == 13)) {
			free_insn_slot(sm, p->ainsn.insn);
			ret = -EFAULT;
		} else {
			if (uregs && pc_dep) {
				memcpy(insns, pc_dep_insn_execbuf, sizeof(insns));
				if (prep_pc_dep_insn_execbuf(insns, insn[0], uregs) != 0) {
					DBPRINTF ("failed to prepare exec buffer for insn %lx!", insn[0]);
					free_insn_slot(sm, p->ainsn.insn);
					return -EINVAL;
				}
				insns[6] = (kprobe_opcode_t)(p->addr + 2);
			} else {
				memcpy(insns, gen_insn_execbuf, sizeof(insns));
				insns[KPROBES_TRAMP_INSN_IDX] = insn[0];
			}
			insns[7] = (kprobe_opcode_t)(p->addr + 1);
			DBPRINTF ("arch_prepare_kprobe: insn %lx", insn[0]);
			DBPRINTF ("arch_prepare_kprobe: to %p - %lx %lx %lx %lx %lx %lx %lx %lx %lx",
				  p->ainsn.insn, insns[0], insns[1], insns[2], insns[3], insns[4],
				  insns[5], insns[6], insns[7], insns[8]);
			memcpy(p->ainsn.insn, insns, sizeof(insns));
			flush_icache_range((long unsigned)p->ainsn.insn, (long unsigned)(p->ainsn.insn) + sizeof(insns));
#ifdef BOARD_tegra
			flush_cache_all();
#endif
		}
	} else {
		free_insn_slot(sm, p->ainsn.insn);
		printk("arch_prepare_kprobe: instruction 0x%lx not instrumentation, addr=0x%p\n", insn[0], p->addr);
	}

	return ret;
}

void prepare_singlestep(struct kprobe *p, struct pt_regs *regs)
{
	if (p->ss_addr) {
		regs->ARM_pc = (unsigned long)p->ss_addr;
		p->ss_addr = NULL;
	} else {
		regs->ARM_pc = (unsigned long)p->ainsn.insn;
	}
}
EXPORT_SYMBOL_GPL(prepare_singlestep);

void save_previous_kprobe(struct kprobe_ctlblk *kcb, struct kprobe *p_run)
{
	kcb->prev_kprobe.kp = kprobe_running();
	kcb->prev_kprobe.status = kcb->kprobe_status;
}

void restore_previous_kprobe(struct kprobe_ctlblk *kcb)
{
	__get_cpu_var(current_kprobe) = kcb->prev_kprobe.kp;
	kcb->kprobe_status = kcb->prev_kprobe.status;
}

void set_current_kprobe(struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
{
	__get_cpu_var(current_kprobe) = p;
	DBPRINTF ("set_current_kprobe: p=%p addr=%p\n", p, p->addr);
}

static int kprobe_handler(struct pt_regs *regs)
{
	struct kprobe *p, *cur;
	struct kprobe_ctlblk *kcb;

	kcb = get_kprobe_ctlblk();
	cur = kprobe_running();
	p = get_kprobe((void *)regs->ARM_pc);

	if (p) {
		if (cur) {
			/* Kprobe is pending, so we're recursing. */
			switch (kcb->kprobe_status) {
			case KPROBE_HIT_ACTIVE:
			case KPROBE_HIT_SSDONE:
				/* A pre- or post-handler probe got us here. */
				kprobes_inc_nmissed_count(p);
				save_previous_kprobe(kcb, NULL);
				set_current_kprobe(p, 0, 0);
				kcb->kprobe_status = KPROBE_REENTER;
				prepare_singlestep(p, regs);
				restore_previous_kprobe(kcb);
				break;
			default:
				/* impossible cases */
				BUG();
			}
		} else {
			set_current_kprobe(p, 0, 0);
			kcb->kprobe_status = KPROBE_HIT_ACTIVE;

			if (!p->pre_handler || !p->pre_handler(p, regs)) {
				kcb->kprobe_status = KPROBE_HIT_SS;
				prepare_singlestep(p, regs);
				reset_current_kprobe();
			}
		}
	} else {
		goto no_kprobe;
	}

	return 0;

no_kprobe:
	printk("no_kprobe: Not one of ours: let kernel handle it %p\n",
			(unsigned long *)regs->ARM_pc);
	return 1;
}

int kprobe_trap_handler(struct pt_regs *regs, unsigned int instr)
{
	int ret;
	unsigned long flags;

#ifdef SUPRESS_BUG_MESSAGES
	int swap_oops_in_progress;
	/* oops_in_progress used to avoid BUG() messages
	 * that slow down kprobe_handler() execution */
	swap_oops_in_progress = oops_in_progress;
	oops_in_progress = 1;
#endif

	local_irq_save(flags);
	preempt_disable();
	ret = kprobe_handler(regs);
	preempt_enable_no_resched();
	local_irq_restore(flags);

#ifdef SUPRESS_BUG_MESSAGES
	oops_in_progress = swap_oops_in_progress;
#endif

	return ret;
}

int setjmp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of(p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry = (kprobe_pre_entry_handler_t)jp->pre_entry;
	entry_point_t entry = (entry_point_t)jp->entry;
	pre_entry = (kprobe_pre_entry_handler_t)jp->pre_entry;

	if (pre_entry) {
		p->ss_addr = (void *)pre_entry (jp->priv_arg, regs);
	}

	if (entry) {
		entry(regs->ARM_r0, regs->ARM_r1, regs->ARM_r2,
		      regs->ARM_r3, regs->ARM_r4, regs->ARM_r5);
	} else {
		dbi_jprobe_return();
	}

	return 0;
}

void dbi_jprobe_return (void)
{
}

int longjmp_break_handler (struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}
EXPORT_SYMBOL_GPL(longjmp_break_handler);

#ifdef CONFIG_STRICT_MEMORY_RWX
extern void mem_text_write_kernel_word(unsigned long *addr, unsigned long word);
#endif

void arch_arm_kprobe(struct kprobe *p)
{
#ifdef CONFIG_STRICT_MEMORY_RWX
	mem_text_write_kernel_word(p->addr, BREAKPOINT_INSTRUCTION);
#else
	*p->addr = BREAKPOINT_INSTRUCTION;
	flush_icache_range((unsigned long)p->addr, (unsigned long)p->addr + sizeof(kprobe_opcode_t));
#endif
}

void arch_disarm_kprobe(struct kprobe *p)
{
#ifdef CONFIG_STRICT_MEMORY_RWX
	mem_text_write_kernel_word(p->addr, p->opcode);
#else
	*p->addr = p->opcode;
	flush_icache_range((unsigned long)p->addr, (unsigned long)p->addr + sizeof(kprobe_opcode_t));
#endif
}

void __naked kretprobe_trampoline(void)
{
	__asm__ __volatile__ (
		"stmdb	sp!, {r0 - r11}		\n\t"
		"mov	r1, sp			\n\t"
		"mov	r0, #0			\n\t"
		"bl	trampoline_probe_handler\n\t"
		"mov	lr, r0			\n\t"
		"ldmia	sp!, {r0 - r11}		\n\t"
		"bx	lr			\n\t"
		: : : "memory");
}

void arch_prepare_kretprobe(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long *ptr_ret_addr;

	/* for __switch_to probe */
	if ((unsigned long)ri->rp->kp.addr == sched_addr) {
		struct thread_info *tinfo = (struct thread_info *)regs->ARM_r2;

		ptr_ret_addr = (unsigned long *)&tinfo->cpu_context.pc;
		ri->sp = NULL;
		ri->task = tinfo->task;
	} else {
		ptr_ret_addr = (unsigned long *)&regs->ARM_lr;
		ri->sp = (unsigned long *)regs->ARM_sp;
	}

	/* Save the return address */
	ri->ret_addr = (unsigned long *)*ptr_ret_addr;

	/* Replace the return addr with trampoline addr */
	*ptr_ret_addr = (unsigned long)&kretprobe_trampoline;
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

int arch_init_kprobes(void)
{
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

	return 0;
}

void arch_exit_kprobes(void)
{
	swap_unregister_undef_hook(&undef_ho_k);
}

/* export symbol for trampoline_arm.h */
EXPORT_SYMBOL_GPL(gen_insn_execbuf);
EXPORT_SYMBOL_GPL(pc_dep_insn_execbuf);
