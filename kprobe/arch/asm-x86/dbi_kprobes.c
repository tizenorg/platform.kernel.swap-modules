/*
 *  Kernel Probes (KProbes)
 *  arch/x86/kernel/kprobes.c
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
 * Copyright (C) IBM Corporation, 2002, 2004
 */

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/arch/asm-x86/dbi_kprobes.c
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
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 * 2012         Stanislav Andreev <s.andreev@samsung.com>: added time debug profiling support; BUG() message fix
 */

#include<linux/module.h>
#include <linux/kdebug.h>

#include "dbi_kprobes.h"
#include "../dbi_kprobes.h"
#include "../../dbi_kprobes.h"

#include "../../dbi_kdebug.h"
#include "../../dbi_insn_slots.h"
#include "../../dbi_kprobes_deps.h"
#include "../../dbi_uprobes.h"

#ifdef OVERHEAD_DEBUG
#include <linux/time.h>
#endif

#define SUPRESS_BUG_MESSAGES

extern struct kprobe * per_cpu__current_kprobe;

extern struct kprobe * per_cpu__current_kprobe;

extern struct kprobe * current_kprobe;

#ifdef OVERHEAD_DEBUG
unsigned long swap_sum_time = 0;
unsigned long swap_sum_hit = 0;
EXPORT_SYMBOL_GPL (swap_sum_time);
EXPORT_SYMBOL_GPL (swap_sum_hit);
#endif

#define SAVE_REGS_STRING		\
	/* Skip cs, ip, orig_ax. */	\
	"	subq $24, %rsp\n"	\
	"	pushq %rdi\n"		\
	"	pushq %rsi\n"		\
	"	pushq %rdx\n"		\
	"	pushq %rcx\n"		\
	"	pushq %rax\n"		\
	"	pushq %r8\n"		\
	"	pushq %r9\n"		\
	"	pushq %r10\n"		\
	"	pushq %r11\n"		\
	"	pushq %rbx\n"		\
	"	pushq %rbp\n"		\
	"	pushq %r12\n"		\
	"	pushq %r13\n"		\
	"	pushq %r14\n"		\
	"	pushq %r15\n"
#define RESTORE_REGS_STRING		\
	"	popq %r15\n"		\
	"	popq %r14\n"		\
	"	popq %r13\n"		\
	"	popq %r12\n"		\
	"	popq %rbp\n"		\
	"	popq %rbx\n"		\
	"	popq %r11\n"		\
	"	popq %r10\n"		\
	"	popq %r9\n"		\
	"	popq %r8\n"		\
	"	popq %rax\n"		\
	"	popq %rcx\n"		\
	"	popq %rdx\n"		\
	"	popq %rsi\n"		\
	"	popq %rdi\n"		\
	/* Skip orig_ax, ip, cs */	\
	"	addq $24, %rsp\n"

DECLARE_MOD_FUNC_DEP(module_alloc, void *, unsigned long size);
DECLARE_MOD_FUNC_DEP(module_free, void, struct module *mod, void *module_region);
DECLARE_MOD_FUNC_DEP(fixup_exception, int, struct pt_regs * regs);

DECLARE_MOD_FUNC_DEP(freeze_processes, int, void);
DECLARE_MOD_FUNC_DEP(thaw_processes, void, void);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
DECLARE_MOD_FUNC_DEP(text_poke, void, void *addr, unsigned char *opcode, int len);
#else
DECLARE_MOD_FUNC_DEP(text_poke, void *, void *addr, const void *opcode, size_t len);
#endif
DECLARE_MOD_FUNC_DEP(show_registers, void, struct pt_regs * regs);

DECLARE_MOD_DEP_WRAPPER (module_alloc, void *, unsigned long size)
IMP_MOD_DEP_WRAPPER (module_alloc, size)

DECLARE_MOD_DEP_WRAPPER (module_free, void, struct module *mod, void *module_region)
IMP_MOD_DEP_WRAPPER (module_free, mod, module_region)

DECLARE_MOD_DEP_WRAPPER (fixup_exception, int, struct pt_regs * regs)
IMP_MOD_DEP_WRAPPER (fixup_exception, regs)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
DECLARE_MOD_DEP_WRAPPER(text_poke, \
			void, void *addr, unsigned char *opcode, int len)
#else
DECLARE_MOD_DEP_WRAPPER(text_poke, \
			void *, void *addr, const void *opcode, size_t len)
#endif
IMP_MOD_DEP_WRAPPER(text_poke, addr, opcode, len)

DECLARE_MOD_DEP_WRAPPER(show_registers, void, struct pt_regs * regs)
IMP_MOD_DEP_WRAPPER(show_registers, regs)

struct kprobe trampoline_p =
{
	.addr = (kprobe_opcode_t *) & kretprobe_trampoline,
	.pre_handler = trampoline_probe_handler
};

/* insert a jmp code */
static __always_inline void set_jmp_op (void *from, void *to)
{
	struct __arch_jmp_op
	{
		char op;
		long raddr;
	} __attribute__ ((packed)) * jop;
	jop = (struct __arch_jmp_op *) from;
	jop->raddr = (long) (to) - ((long) (from) + 5);
	jop->op = RELATIVEJUMP_INSTRUCTION;
}

static void set_user_jmp_op (void *from, void *to)
{
	struct __arch_jmp_op
	{
		char op;
		long raddr;
	} __attribute__ ((packed)) jop;
	//jop = (struct __arch_jmp_op *) from;
	jop.raddr = (long) (to) - ((long) (from) + 5);
	jop.op = RELATIVEJUMP_INSTRUCTION;
	if (!write_proc_vm_atomic (current, (unsigned long)from, &jop, sizeof(jop)))
		panic ("failed to write jump opcode to user space %p!\n", from);
}

/*
 * returns non-zero if opcodes can be boosted.
 */
static __always_inline int can_boost (kprobe_opcode_t * opcodes)
{
#define W(row,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf)		      \
	(((b0##UL << 0x0)|(b1##UL << 0x1)|(b2##UL << 0x2)|(b3##UL << 0x3) |   \
	  (b4##UL << 0x4)|(b5##UL << 0x5)|(b6##UL << 0x6)|(b7##UL << 0x7) |   \
	  (b8##UL << 0x8)|(b9##UL << 0x9)|(ba##UL << 0xa)|(bb##UL << 0xb) |   \
	  (bc##UL << 0xc)|(bd##UL << 0xd)|(be##UL << 0xe)|(bf##UL << 0xf))    \
	 << (row % 32))
	/*
	 * Undefined/reserved opcodes, conditional jump, Opcode Extension
	 * Groups, and some special opcodes can not be boost.
	 */
	static const unsigned long twobyte_is_boostable[256 / 32] = {
		/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
		/*      -------------------------------         */
		W (0x00, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0) |	/* 00 */
			W (0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),	/* 10 */
		W (0x20, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) |	/* 20 */
			W (0x30, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),	/* 30 */
		W (0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) |	/* 40 */
			W (0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),	/* 50 */
		W (0x60, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1) |	/* 60 */
			W (0x70, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1),	/* 70 */
		W (0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) |	/* 80 */
			W (0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1),	/* 90 */
		W (0xa0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1) |	/* a0 */
			W (0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1),	/* b0 */
		W (0xc0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1) |	/* c0 */
			W (0xd0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1),	/* d0 */
		W (0xe0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1) |	/* e0 */
			W (0xf0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0)	/* f0 */
			/*      -------------------------------         */
			/*      0 1 2 3 4 5 6 7 8 9 a b c d e f         */
	};
#undef W
	kprobe_opcode_t opcode;
	kprobe_opcode_t *orig_opcodes = opcodes;
retry:
	if (opcodes - orig_opcodes > MAX_INSN_SIZE - 1)
		return 0;
	opcode = *(opcodes++);

	/* 2nd-byte opcode */
	if (opcode == 0x0f)
	{
		if (opcodes - orig_opcodes > MAX_INSN_SIZE - 1)
			return 0;
		return test_bit (*opcodes, twobyte_is_boostable);
	}

	switch (opcode & 0xf0)
	{
		case 0x60:
			if (0x63 < opcode && opcode < 0x67)
				goto retry;	/* prefixes */
			/* can't boost Address-size override and bound */
			return (opcode != 0x62 && opcode != 0x67);
		case 0x70:
			return 0;	/* can't boost conditional jump */
		case 0xc0:
			/* can't boost software-interruptions */
			return (0xc1 < opcode && opcode < 0xcc) || opcode == 0xcf;
		case 0xd0:
			/* can boost AA* and XLAT */
			return (opcode == 0xd4 || opcode == 0xd5 || opcode == 0xd7);
		case 0xe0:
			/* can boost in/out and absolute jmps */
			return ((opcode & 0x04) || opcode == 0xea);
		case 0xf0:
			if ((opcode & 0x0c) == 0 && opcode != 0xf1)
				goto retry;	/* lock/rep(ne) prefix */
			/* clear and set flags can be boost */
			return (opcode == 0xf5 || (0xf7 < opcode && opcode < 0xfe));
		default:
			if (opcode == 0x26 || opcode == 0x36 || opcode == 0x3e)
				goto retry;	/* prefixes */
			/* can't boost CS override and call */
			return (opcode != 0x2e && opcode != 0x9a);
	}
}

/*
 * returns non-zero if opcode modifies the interrupt flag.
 */
static int is_IF_modifier (kprobe_opcode_t opcode)
{
	switch (opcode)
	{
		case 0xfa:		/* cli */
		case 0xfb:		/* sti */
		case 0xcf:		/* iret/iretd */
		case 0x9d:		/* popf/popfd */
			return 1;
	}
	return 0;
}

int arch_check_insn (struct arch_specific_insn *ainsn)
{
	DBPRINTF("Warrning: arch_check_insn is not implemented for x86\n");
	return 0;
}

int arch_prepare_kprobe (struct kprobe *p)
{
	kprobe_opcode_t insns[KPROBES_TRAMP_LEN];

	int ret = 0;

	if ((unsigned long) p->addr & 0x01)
	{
		DBPRINTF ("Attempt to register kprobe at an unaligned address\n");
		//ret = -EINVAL;
	}


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
		}

		if (can_boost (p->addr))
			p->ainsn.boostable = 0;
		else
			p->ainsn.boostable = -1;
		memcpy (p->ainsn.insn, insn, MAX_INSN_SIZE * sizeof (kprobe_opcode_t));
	}
	else
	{
		free_insn_slot(&kprobe_insn_pages, NULL, p->ainsn.insn);
	}

	return ret;
}

int arch_prepare_uprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	int ret = 0;
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN];

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
			if (can_boost (insn))
				p->ainsn.boostable = 0;
			else
				p->ainsn.boostable = -1;
			memcpy (&insns[UPROBES_TRAMP_INSN_IDX], insn, MAX_INSN_SIZE*sizeof(kprobe_opcode_t));
			insns[UPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;

			if (!write_proc_vm_atomic (task, (unsigned long) p->ainsn.insn, insns, sizeof (insns)))
			{
				panic("failed to write memory %p!\n", p->ainsn.insn);
				DBPRINTF ("failed to write insn slot to process memory: insn %p, addr %p, probe %p!", insn, p->ainsn.insn, p->addr);
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
		regs->EREG (ip) = (unsigned long)p->ss_addr;
		p->ss_addr = NULL;
	}
	else
	{
		regs->EREG (flags) |= TF_MASK;
		regs->EREG (flags) &= ~IF_MASK;
		/*single step inline if the instruction is an int3 */
		if (p->opcode == BREAKPOINT_INSTRUCTION){
			regs->EREG (ip) = (unsigned long) p->addr;
			//printk("break_insn!!!\n");
		}
		else
			regs->EREG (ip) = (unsigned long) p->ainsn.insn;
	}
}


void save_previous_kprobe (struct kprobe_ctlblk *kcb, struct kprobe *cur_p)
{
	if (kcb->prev_kprobe.kp != NULL)
	{
		panic ("no space to save new probe[]: task = %d/%s, prev %d/%p, current %d/%p, new %d/%p,",
				current->pid, current->comm, kcb->prev_kprobe.kp->tgid, kcb->prev_kprobe.kp->addr,
				kprobe_running()->tgid, kprobe_running()->addr, cur_p->tgid, cur_p->addr);
	}


	kcb->prev_kprobe.kp = kprobe_running();
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
	kcb->kprobe_saved_eflags = kcb->kprobe_old_eflags = (regs->EREG (flags) & (TF_MASK | IF_MASK));
	if (is_IF_modifier (p->opcode))
		kcb->kprobe_saved_eflags &= ~IF_MASK;
}

int kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *p = 0;
	int ret = 0, pid = 0, retprobe = 0, reenter = 0;
	kprobe_opcode_t *addr = NULL;
	struct kprobe_ctlblk *kcb;
#ifdef OVERHEAD_DEBUG
	struct timeval swap_tv1;
	struct timeval swap_tv2;
#endif
#ifdef SUPRESS_BUG_MESSAGES
	int swap_oops_in_progress;
#endif

	/* We're in an interrupt, but this is clear and BUG()-safe. */
	addr = (kprobe_opcode_t *) (regs->EREG (ip) - sizeof (kprobe_opcode_t));
	DBPRINTF ("KPROBE: regs->eip = 0x%lx addr = 0x%p\n", regs->EREG (ip), addr);
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

	if (user_mode_vm(regs))
	{
		//printk("exception[%lu] from user mode %s/%u/%u addr %p.\n", nCount, current->comm, current->pid, current->tgid, addr);
		pid = current->tgid;
	}

	/* Check we're not actually recursing */
	if (kprobe_running ())
	{
		DBPRINTF ("lock???");
		p = get_kprobe(addr, pid);
		if (p)
		{
			DBPRINTF ("reenter p = %p", p);
			if(!pid){
				if (kcb->kprobe_status == KPROBE_HIT_SS && *p->ainsn.insn == BREAKPOINT_INSTRUCTION)
				{
					regs->EREG (flags) &= ~TF_MASK;
					regs->EREG (flags) |= kcb->kprobe_saved_eflags;
					goto no_kprobe;
				}
			}
			else {
				//#warning BREAKPOINT_INSTRUCTION user mode handling is missed!!!
			}

			/* We have reentered the kprobe_handler(), since
			 * another probe was hit while within the handler.
			 * We here save the original kprobes variables and
			 * just single step on the instruction of the new probe
			 * without calling any user handlers.
			 */
			save_previous_kprobe (kcb, p);
			set_current_kprobe (p, regs, kcb);
			kprobes_inc_nmissed_count (p);
			prepare_singlestep (p, regs);
			kcb->kprobe_status = KPROBE_REENTER;
			// FIXME should we enable preemption here??...
			//preempt_enable_no_resched ();
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
		else
		{
			if(!pid){
				if (*addr != BREAKPOINT_INSTRUCTION)
				{
					/* The breakpoint instruction was removed by
					 * another cpu right after we hit, no further
					 * handling of this interrupt is appropriate
					 */
					regs->EREG (ip) -= sizeof (kprobe_opcode_t);
					ret = 1;
					goto no_kprobe;
				}
			}
			else {
				//#warning BREAKPOINT_INSTRUCTION user mode handling is missed!!!
				//we can reenter probe upon uretprobe exception
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
			if(!p){
				p = __get_cpu_var (current_kprobe);
				if(p->tgid)
					panic("after uhandler");
				DBPRINTF ("kprobe_running !!! p = 0x%p p->break_handler = 0x%p", p, p->break_handler);
				if (p->break_handler && p->break_handler (p, regs))
				{
					DBPRINTF ("kprobe_running !!! goto ss");
					goto ss_probe;
				}
				DBPRINTF ("kprobe_running !!! goto no");
				DBPRINTF ("no_kprobe");
				goto no_kprobe;
			}
		}
	}

	DBPRINTF ("get_kprobe %p", addr);
	if (!p)
		p = get_kprobe(addr, pid);
	if (!p)
	{
		if(!pid){
			if (*addr != BREAKPOINT_INSTRUCTION)
			{
				/*
				 * The breakpoint instruction was removed right
				 * after we hit it.  Another cpu has removed
				 * either a probepoint or a debugger breakpoint
				 * at this address.  In either case, no further
				 * handling of this interrupt is appropriate.
				 * Back up over the (now missing) int3 and run
				 * the original instruction.
				 */
				regs->EREG (ip) -= sizeof (kprobe_opcode_t);
				ret = 1;
			}
		}
		else {
			//#warning BREAKPOINT_INSTRUCTION user mode handling is missed!!!
			DBPRINTF ("search UNDEF_INSTRUCTION %p\n", addr);
			// UNDEF_INSTRUCTION from user space
			p = get_kprobe_by_insn_slot (addr-UPROBES_TRAMP_RET_BREAK_IDX, pid, current);
			if (!p) {
				// Not one of ours: let kernel handle it
				DBPRINTF ("no_kprobe");
				//printk("no_kprobe2 ret = %d\n", ret);
				goto no_kprobe;
			}
			retprobe = 1;
			DBPRINTF ("uretprobe %p\n", addr);
		}
		if(!p) {
			/* Not one of ours: let kernel handle it */
			DBPRINTF ("no_kprobe");
			goto no_kprobe;
		}
	}
	set_current_kprobe (p, regs, kcb);
	if(!reenter)
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;

	if (retprobe)		//(einsn == UNDEF_INSTRUCTION)
		ret = trampoline_probe_handler (p, regs);
	else if (p->pre_handler)
		ret = p->pre_handler (p, regs);

	if (ret)
	{
		if (ret == 2) { // we have alreadyc called the handler, so just single step the instruction
			DBPRINTF ("p->pre_handler[] 2");
			goto ss_probe;
		}
		DBPRINTF ("p->pre_handler[] 1");
		// FIXME should we enable preemption here??...
		//preempt_enable_no_resched ();
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
	DBPRINTF ("p->pre_handler[] 0");

ss_probe:
	DBPRINTF ("p = %p\n", p);
	DBPRINTF ("p->opcode = 0x%lx *p->addr = 0x%lx p->addr = 0x%p\n", (unsigned long) p->opcode, p->tgid ? 0 : (unsigned long) (*p->addr), p->addr);

#if !defined(CONFIG_PREEMPT) || defined(CONFIG_PM)
	if (p->ainsn.boostable == 1 && !p->post_handler)
	{
		/* Boost up -- we can execute copied instructions directly */
		reset_current_kprobe ();
		regs->EREG (ip) = (unsigned long) p->ainsn.insn;
		preempt_enable_no_resched ();
#ifdef OVERHEAD_DEBUG
		do_gettimeofday(&swap_tv2);
		swap_sum_hit++;
		swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) *  USEC_IN_SEC_NUM +
			(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
		oops_in_progress = swap_oops_in_progress;
#endif
		return 1;
	}
#endif // !CONFIG_PREEMPT
	prepare_singlestep (p, regs);
	kcb->kprobe_status = KPROBE_HIT_SS;
	// FIXME should we enable preemption here??...
	//preempt_enable_no_resched ();
#ifdef OVERHEAD_DEBUG
	do_gettimeofday(&swap_tv2);
	swap_sum_hit++;
	swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) *  USEC_IN_SEC_NUM +
		(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
	oops_in_progress = swap_oops_in_progress;
#endif
	return 1;

no_kprobe:

	preempt_enable_no_resched ();
#ifdef OVERHEAD_DEBUG
	do_gettimeofday(&swap_tv2);
	swap_sum_hit++;
	swap_sum_time += ((swap_tv2.tv_sec - swap_tv1.tv_sec) *  USEC_IN_SEC_NUM +
		(swap_tv2.tv_usec - swap_tv1.tv_usec));
#endif
#ifdef SUPRESS_BUG_MESSAGES
	oops_in_progress = swap_oops_in_progress;
#endif
	return ret;
}

int setjmp_pre_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct jprobe *jp = container_of (p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry;
	entry_point_t entry;

	unsigned long addr, args[6];
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	DBPRINTF ("setjmp_pre_handler %p:%d", p->addr, p->tgid);
	pre_entry = (kprobe_pre_entry_handler_t) jp->pre_entry;
	entry = (entry_point_t) jp->entry;

	if (!p->tgid || (p->tgid == current->tgid)) {
		/* handle __switch_to probe */
		if(!p->tgid && (p->addr == sched_addr) && sched_rp) {
			struct thread_info *tinfo = NULL; //TODO implement for x86
			patch_suspended_task(sched_rp, tinfo->task);
		}
	}

	if (p->tgid) {
		/* FIXME some user space apps crash if we clean interrupt bit */
		//regs->EREG(flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		trace_hardirqs_off ();
#endif
		if (p->tgid == current->tgid) {
			// read first 6 args from stack
			if (!read_proc_vm_atomic (current, regs->EREG(sp) + 4, args, sizeof(args)))
				panic ("failed to read user space func arguments %lx!\n", regs->EREG(sp)+4);
			if (pre_entry)
				p->ss_addr = pre_entry (jp->priv_arg, regs);
			if (entry)
				entry (args[0], args[1], args[2], args[3], args[4], args[5]);
		} else {
			dbi_arch_uprobe_return();
		}

		return 2;
	} else {
		kcb->jprobe_saved_regs = *regs;
		kcb->jprobe_saved_esp = &regs->EREG(sp);
		addr = (unsigned long) (kcb->jprobe_saved_esp);

		/* TBD: As Linus pointed out, gcc assumes that the callee
		 * owns the argument space and could overwrite it, e.g.
		 * tailcall optimization. So, to be absolutely safe
		 * we also save and restore enough stack bytes to cover
		 * the argument area. */
		memcpy (kcb->jprobes_stack, (kprobe_opcode_t *)addr, MIN_STACK_SIZE (addr));
		regs->EREG (flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		trace_hardirqs_off ();
#endif
		if (pre_entry)
			p->ss_addr = pre_entry(jp->priv_arg, regs);
		regs->EREG(ip) = (unsigned long) (jp->entry);
	}

	return 1;

#if 0 /* initial version */
	struct jprobe *jp = container_of (p, struct jprobe, kp);
	kprobe_pre_entry_handler_t pre_entry;
	entry_point_t entry;

	unsigned long addr, args[6];
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	DBPRINTF ("setjmp_pre_handler %p:%d", p->addr, p->tgid);
	pre_entry = (kprobe_pre_entry_handler_t) jp->pre_entry;
	entry = (entry_point_t) jp->entry;
	if(p->tgid) {
		regs->EREG (flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		trace_hardirqs_off ();
#endif
		if (p->tgid == current->tgid)
		{
			// read first 6 args from stack
			if (!read_proc_vm_atomic (current, regs->EREG(sp)+4, args, sizeof(args)))
				panic ("failed to read user space func arguments %lx!\n", regs->EREG(sp)+4);
			if (pre_entry)
				p->ss_addr = pre_entry (jp->priv_arg, regs);
			if (entry)
				entry (args[0], args[1], args[2], args[3], args[4], args[5]);
		}
		else
			dbi_arch_uprobe_return ();

		return 2;
	}
	else {
		kcb->jprobe_saved_regs = *regs;
		kcb->jprobe_saved_esp = &regs->EREG (sp);
		addr = (unsigned long) (kcb->jprobe_saved_esp);

		/*
		 * TBD: As Linus pointed out, gcc assumes that the callee
		 * owns the argument space and could overwrite it, e.g.
		 * tailcall optimization. So, to be absolutely safe
		 * we also save and restore enough stack bytes to cover
		 * the argument area.
		 */
		memcpy (kcb->jprobes_stack, (kprobe_opcode_t *) addr, MIN_STACK_SIZE (addr));
		regs->EREG (flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		trace_hardirqs_off ();
#endif
		if (pre_entry)
			p->ss_addr = pre_entry (jp->priv_arg, regs);
		regs->EREG (ip) = (unsigned long) (jp->entry);
	}

	return 1;
#endif /* 0 */
}

void dbi_jprobe_return (void)
{
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	asm volatile("       xchgl   %%ebx,%%esp     \n"
			"       int3			\n"
			"       .globl dbi_jprobe_return_end	\n"
			"       dbi_jprobe_return_end:	\n"
			"       nop			\n"::"b" (kcb->jprobe_saved_esp):"memory");
}

void dbi_arch_uprobe_return (void)
{
	DBPRINTF("dbi_arch_uprobe_return (void) is empty");
}

/*
 * Called after single-stepping.  p->addr is the address of the
 * instruction whose first byte has been replaced by the "int 3"
 * instruction.  To avoid the SMP problems that can occur when we
 * temporarily put back the original opcode to single-step, we
 * single-stepped a copy of the instruction.  The address of this
 * copy is p->ainsn.insn.
 *
 * This function prepares to return from the post-single-step
 * interrupt.  We have to fix up the stack as follows:
 *
 * 0) Except in the case of absolute or indirect jump or call instructions,
 * the new eip is relative to the copied instruction.  We need to make
 * it relative to the original instruction.
 *
 * 1) If the single-stepped instruction was pushfl, then the TF and IF
 * flags are set in the just-pushed eflags, and may need to be cleared.
 *
 * 2) If the single-stepped instruction was a call, the return address
 * that is atop the stack is the address following the copied instruction.
 * We need to make it the address following the original instruction.
 *
 * This function also checks instruction size for preparing direct execution.
 */
static void resume_execution (struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb)
{
	unsigned long *tos, tos_dword = 0;
	unsigned long copy_eip = (unsigned long) p->ainsn.insn;
	unsigned long orig_eip = (unsigned long) p->addr;
	kprobe_opcode_t insns[2];

	regs->EREG (flags) &= ~TF_MASK;

	if(p->tgid){
		tos = (unsigned long *) &tos_dword;
		if (!read_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
			panic ("failed to read dword from top of the user space stack %lx!\n", regs->EREG (sp));
		if (!read_proc_vm_atomic (current, (unsigned long)p->ainsn.insn, insns, 2*sizeof(kprobe_opcode_t)))
			panic ("failed to read first 2 opcodes of instruction copy from user space %p!\n", p->ainsn.insn);
	}
	else {
		tos = (unsigned long *) &regs->EREG (sp);
		insns[0] = p->ainsn.insn[0];
		insns[1] = p->ainsn.insn[1];
	}

	switch (insns[0])
	{
		case 0x9c:		/* pushfl */
			*tos &= ~(TF_MASK | IF_MASK);
			*tos |= kcb->kprobe_old_eflags;
			break;
		case 0xc2:		/* iret/ret/lret */
		case 0xc3:
		case 0xca:
		case 0xcb:
		case 0xcf:
		case 0xea:		/* jmp absolute -- eip is correct */
			/* eip is already adjusted, no more changes required */
			p->ainsn.boostable = 1;
			goto no_change;
		case 0xe8:		/* call relative - Fix return addr */
			*tos = orig_eip + (*tos - copy_eip);
			break;
		case 0x9a:		/* call absolute -- same as call absolute, indirect */
			*tos = orig_eip + (*tos - copy_eip);
			if(p->tgid){
				if (!write_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
					panic ("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));
			}
			goto no_change;
		case 0xff:
			if ((insns[1] & 0x30) == 0x10)
			{
				/*
				 * call absolute, indirect
				 * Fix return addr; eip is correct.
				 * But this is not boostable
				 */
				*tos = orig_eip + (*tos - copy_eip);
				if(p->tgid){
					if (!write_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
						panic ("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));
				}
				goto no_change;
			}
			else if (((insns[1] & 0x31) == 0x20) ||	/* jmp near, absolute indirect */
					((insns[1] & 0x31) == 0x21))
			{		/* jmp far, absolute indirect */
				/* eip is correct. And this is boostable */
				p->ainsn.boostable = 1;
				goto no_change;
			}
		default:
			break;
	}

	if(p->tgid){
		if (!write_proc_vm_atomic (current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
			panic ("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));
	}

	if (p->ainsn.boostable == 0)
	{
		if ((regs->EREG (ip) > copy_eip) && (regs->EREG (ip) - copy_eip) + 5 < MAX_INSN_SIZE)
		{
			/*
			 * These instructions can be executed directly if it
			 * jumps back to correct address.
			 */
			if(p->tgid)
				set_user_jmp_op ((void *) regs->EREG (ip), (void *) orig_eip + (regs->EREG (ip) - copy_eip));
			else
				set_jmp_op ((void *) regs->EREG (ip), (void *) orig_eip + (regs->EREG (ip) - copy_eip));
			p->ainsn.boostable = 1;
		}
		else
		{
			p->ainsn.boostable = -1;
		}
	}

	regs->EREG (ip) = orig_eip + (regs->EREG (ip) - copy_eip);

no_change:
	return;
}

/*
 * Interrupts are disabled on entry as trap1 is an interrupt gate and they
 * remain disabled thoroughout this function.
 */
static int post_kprobe_handler (struct pt_regs *regs)
{
	struct kprobe *cur = kprobe_running ();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	if (!cur)
		return 0;
	if ((kcb->kprobe_status != KPROBE_REENTER) && cur->post_handler)
	{
		kcb->kprobe_status = KPROBE_HIT_SSDONE;
		cur->post_handler (cur, regs, 0);
	}

	resume_execution (cur, regs, kcb);
	regs->EREG (flags) |= kcb->kprobe_saved_eflags;
#ifndef CONFIG_X86
	trace_hardirqs_fixup_flags (regs->EREG (flags));
#endif // CONFIG_X86
	/*Restore back the original saved kprobes variables and continue. */
	if (kcb->kprobe_status == KPROBE_REENTER)
	{
		restore_previous_kprobe (kcb);
		goto out;
	}
	reset_current_kprobe ();
out:
	preempt_enable_no_resched ();

	/*
	 * if somebody else is singlestepping across a probe point, eflags
	 * will have TF set, in which case, continue the remaining processing
	 * of do_debug, as if this is not a probe hit.
	 */
	if (regs->EREG (flags) & TF_MASK)
		return 0;

	return 1;
}

int kprobe_fault_handler (struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur = kprobe_running ();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();

	switch (kcb->kprobe_status)
	{
		case KPROBE_HIT_SS:
		case KPROBE_REENTER:
			/*
			 * We are here because the instruction being single
			 * stepped caused a page fault. We reset the current
			 * kprobe and the eip points back to the probe address
			 * and allow the page fault handler to continue as a
			 * normal page fault.
			 */
			regs->EREG (ip) = (unsigned long) cur->addr;
			regs->EREG (flags) |= kcb->kprobe_old_eflags;
			if (kcb->kprobe_status == KPROBE_REENTER)
				restore_previous_kprobe (kcb);
			else
				reset_current_kprobe ();
			preempt_enable_no_resched ();
			break;
		case KPROBE_HIT_ACTIVE:
		case KPROBE_HIT_SSDONE:
			/*
			 * We increment the nmissed count for accounting,
			 * we can also use npre/npostfault count for accouting
			 * these specific fault cases.
			 */
			kprobes_inc_nmissed_count (cur);

			/*
			 * We come here because instructions in the pre/post
			 * handler caused the page_fault, this could happen
			 * if handler tries to access user space by
			 * copy_from_user(), get_user() etc. Let the
			 * user-specified handler try to fix it first.
			 */
			if (cur->fault_handler && cur->fault_handler (cur, regs, trapnr))
				return 1;

			/*
			 * In case the user-specified fault handler returned
			 * zero, try to fix up.
			 */
			if (fixup_exception (regs))
				return 1;

			/*
			 * fixup_exception() could not handle it,
			 * Let do_page_fault() fix it.
			 */
			break;
		default:
			break;
	}
	return 0;
}

int kprobe_exceptions_notify (struct notifier_block *self, unsigned long val, void *data)
{
	struct die_args *args = (struct die_args *) data;
	int ret = NOTIFY_DONE;

	DBPRINTF ("val = %ld, data = 0x%X", val, (unsigned int) data);

	/*if (args->regs && user_mode_vm (args->regs))
	  return ret;*/

	DBPRINTF ("switch (val) %lu %d %d", val, DIE_INT3, DIE_TRAP);
	switch (val)
	{
#ifdef CONFIG_KPROBES
		case DIE_INT3:
#else
		case DIE_TRAP:
#endif
			DBPRINTF ("before kprobe_handler ret=%d %p", ret, args->regs);
			if (kprobe_handler (args->regs))
				ret = NOTIFY_STOP;
			DBPRINTF ("after kprobe_handler ret=%d %p", ret, args->regs);
			break;
		case DIE_DEBUG:
			if (post_kprobe_handler (args->regs))
				ret = NOTIFY_STOP;
			break;
		case DIE_GPF:
			// kprobe_running() needs smp_processor_id()
			preempt_disable ();
			if (kprobe_running () && kprobe_fault_handler (args->regs, args->trapnr))
				ret = NOTIFY_STOP;
			preempt_enable ();
			break;
		default:
			break;
	}
	DBPRINTF ("ret=%d", ret);
	/* if(ret == NOTIFY_STOP) */
	/* 	handled_exceptions++; */

	return ret;
}

static struct notifier_block kprobe_exceptions_nb = {
	.notifier_call = kprobe_exceptions_notify,
	.priority = INT_MAX
};

int longjmp_break_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk ();
	u8 *addr = (u8 *) (regs->EREG (ip) - 1);
	unsigned long stack_addr = (unsigned long) (kcb->jprobe_saved_esp);
	struct jprobe *jp = container_of (p, struct jprobe, kp);

	DBPRINTF ("p = %p\n", p);

	if ((addr > (u8 *) dbi_jprobe_return) && (addr < (u8 *) dbi_jprobe_return_end))
	{
		if ((unsigned long *)(&regs->EREG(sp)) != kcb->jprobe_saved_esp)
		{
			struct pt_regs *saved_regs = &kcb->jprobe_saved_regs;
			printk ("current esp %p does not match saved esp %p\n", &regs->EREG (sp), kcb->jprobe_saved_esp);
			printk ("Saved registers for jprobe %p\n", jp);
			show_registers (saved_regs);
			printk ("Current registers\n");
			show_registers (regs);
			panic("BUG");
			//BUG ();
		}
		*regs = kcb->jprobe_saved_regs;
		memcpy ((kprobe_opcode_t *) stack_addr, kcb->jprobes_stack, MIN_STACK_SIZE (stack_addr));
		preempt_enable_no_resched ();
		return 1;
	}
}

void arch_arm_kprobe (struct kprobe *p)
{
	text_poke (p->addr, ((unsigned char[])
				{BREAKPOINT_INSTRUCTION}), 1);
}

void arch_disarm_kprobe (struct kprobe *p)
{
	text_poke (p->addr, &p->opcode, 1);
}

void * trampoline_probe_handler_x86 (struct pt_regs *regs)
{
	return (void *)trampoline_probe_handler(NULL, regs);
}




/*
 * Called when the probe at kretprobe trampoline is hit
 */
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

	if(!p){ // X86 kernel space
		DBPRINTF ("regs %p", regs);
		/* fixup registers */
		regs->XREG (cs) = __KERNEL_CS | get_kernel_rpl ();
		regs->EREG (ip) = trampoline_address;
		regs->ORIG_EAX_REG = 0xffffffff;
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

			if(!p){ // X86 kernel space
				__get_cpu_var (current_kprobe) = &ri->rp->kp;
				get_kprobe_ctlblk ()->kprobe_status = KPROBE_HIT_ACTIVE;
			}

			ri->rp->handler (ri, regs, ri->rp->priv_arg);

			if(!p) // X86 kernel space
				__get_cpu_var (current_kprobe) = NULL;

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

	if(p){ // X86 user space
		regs->EREG(ip) = orig_ret_address;
		//printk (" uretprobe regs->eip = 0x%lx\n", regs->EREG(ip));
	}

	if(p){ // ARM, MIPS, X86 user space
		if (kcb->kprobe_status == KPROBE_REENTER)
			restore_previous_kprobe (kcb);
		else
			reset_current_kprobe ();
	}

	hlist_for_each_entry_safe (ri, node, tmp, &empty_rp, hlist)
	{
		hlist_del (&ri->hlist);
		kfree (ri);
	}
	spin_unlock_irqrestore (&kretprobe_lock, flags);

	if(!p) // X86 kernel space
		return (int)orig_ret_address;

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
		ri->sp = (kprobe_opcode_t *)regs->EREG(sp);

		/* Replace the return addr with trampoline addr */
		if (rp->kp.tgid){
			unsigned long ra = (unsigned long) (rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);/*, stack[6];
													       if (!read_proc_vm_atomic (current, regs->EREG(sp), stack, sizeof(stack)))
													       panic ("failed to read user space func stack %lx!\n", regs->EREG(sp));
													       printk("stack: %lx %lx %lx %lx %lx %lx\n", stack[0], stack[1], stack[2], stack[3], stack[4], stack[5]);*/
			if (!read_proc_vm_atomic (current, regs->EREG(sp), &(ri->ret_addr), sizeof(ri->ret_addr)))
				panic ("failed to read user space func ra %lx!\n", regs->EREG(sp));
			if (!write_proc_vm_atomic (current, regs->EREG(sp), &ra, sizeof(ra)))
				panic ("failed to write user space func ra %lx!\n", regs->EREG(sp));
			//printk("__arch_prepare_kretprobe: ra %lx %p->%lx\n",regs->EREG(sp), ri->ret_addr, ra);
		}
		else {
			unsigned long *sara = (unsigned long *)&regs->EREG(sp);
			ri->ret_addr = (kprobe_opcode_t *)*sara;
			*sara = (unsigned long)&kretprobe_trampoline;
			DBPRINTF ("ra loc %p, origr_ra %p new ra %lx\n", sara, ri->ret_addr, *sara);
		}

		add_rp_inst (ri);
	}
	else {
		DBPRINTF ("WARNING: missed retprobe %p\n", rp->kp.addr);
		rp->nmissed++;
	}
}


int arch_init_module_deps()
{
	INIT_MOD_DEP_VAR(module_alloc, module_alloc);
	INIT_MOD_DEP_VAR(module_free, module_free);
	INIT_MOD_DEP_VAR(fixup_exception, fixup_exception);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
# error this kernel version has no text_poke function which is necessaryf for x86 ach!!!
#else
	INIT_MOD_DEP_VAR(text_poke, text_poke);
#endif
	INIT_MOD_DEP_VAR(show_registers, show_registers);
#if defined(CONFIG_PREEMPT) && defined(CONFIG_PM)
	INIT_MOD_DEP_VAR(freeze_processes, freeze_processes);
	INIT_MOD_DEP_VAR(thaw_processes, thaw_processes);
#endif

	return 0;
}

int __init arch_init_kprobes (void)
{
	if (arch_init_module_dependencies())
	{
		DBPRINTF ("Unable to init module dependencies\n");
		return -1;
	}

	return register_die_notifier (&kprobe_exceptions_nb);
}

void __exit dbi_arch_exit_kprobes (void)
{
	unregister_die_notifier (&kprobe_exceptions_nb);
}

//EXPORT_SYMBOL_GPL (dbi_arch_uprobe_return);
//EXPORT_SYMBOL_GPL (dbi_arch_exit_kprobes);
