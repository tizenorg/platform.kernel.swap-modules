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
#include <kprobe/dbi_kprobes.h>

#include <kprobe/dbi_kdebug.h>
#include <kprobe/dbi_insn_slots.h>
#include <kprobe/dbi_kprobes_deps.h>
#include <ksyms/ksyms.h>

#include <asm/cacheflush.h>
#include <asm/traps.h>
#include <asm/ptrace.h>
#include <linux/list.h>
#include <linux/hash.h>

#define SUPRESS_BUG_MESSAGES

#define sign_extend(x, signbit) ((x) | (0 - ((x) & (1 << (signbit)))))
#define branch_displacement(insn) sign_extend(((insn) & 0xffffff) << 2, 25)

extern struct kprobe * per_cpu__current_kprobe;
extern struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];

static void (*__swap_register_undef_hook)(struct undef_hook *hook);
static void (*__swap_unregister_undef_hook)(struct undef_hook *hook);

static unsigned long get_addr_b(unsigned long insn, unsigned long addr)
{
	/* real position less then PC by 8 */
	return (kprobe_opcode_t)((long)addr + 8 + branch_displacement(insn));
}

static int prep_pc_dep_insn_execbuf(kprobe_opcode_t *insns,
				    kprobe_opcode_t insn, int uregs)
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

static int arch_check_insn_arm(unsigned long insn)
{
	/* check instructions that can change PC by nature */
	if (
	 /* ARM_INSN_MATCH(UNDEF, insn) || */
	    ARM_INSN_MATCH(AUNDEF, insn) ||
	    ARM_INSN_MATCH(SWI, insn) ||
	    ARM_INSN_MATCH(BREAK, insn) ||
	    ARM_INSN_MATCH(BXJ, insn)) {
		goto bad_insn;
#ifndef CONFIG_CPU_V7
	/* check instructions that can write result to PC */
	} else if ((ARM_INSN_MATCH(DPIS, insn) ||
		    ARM_INSN_MATCH(DPRS, insn) ||
		    ARM_INSN_MATCH(DPI, insn) ||
		    ARM_INSN_MATCH(LIO, insn) ||
		    ARM_INSN_MATCH(LRO, insn)) &&
		   (ARM_INSN_REG_RD(insn) == 15)) {
		goto bad_insn;
#endif /* CONFIG_CPU_V7 */
	/* check special instruction loads store multiple registers */
	} else if ((ARM_INSN_MATCH(LM, insn) || ARM_INSN_MATCH(SM, insn)) &&
			/* store PC or load to PC */
		   (ARM_INSN_REG_MR(insn, 15) ||
			 /* store/load with PC update */
		    ((ARM_INSN_REG_RN(insn) == 15) && (insn & 0x200000)))) {
		goto bad_insn;
	}

	return 0;

bad_insn:
	printk("Bad insn arch_check_insn_arm: %lx\n", insn);
	return -EFAULT;
}

static int make_branch_tarmpoline(unsigned long addr, unsigned long insn,
				  unsigned long *tramp)
{
	int ok = 0;

	/* B */
	if (ARM_INSN_MATCH(B, insn) &&
	    !ARM_INSN_MATCH(BLX1, insn)) {
		/* B check can be false positive on BLX1 instruction */
		memcpy(tramp, b_cond_insn_execbuf, KPROBES_TRAMP_LEN);
		tramp[KPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
		tramp[0] |= insn & 0xf0000000;
		tramp[6] = get_addr_b(insn, addr);
		tramp[7] = addr + 4;
		ok = 1;
	/* BX, BLX (Rm) */
	} else if (ARM_INSN_MATCH(BX, insn) ||
		   ARM_INSN_MATCH(BLX2, insn)) {
		memcpy(tramp, b_r_insn_execbuf, KPROBES_TRAMP_LEN);
		tramp[0] = insn;
		tramp[KPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
		tramp[7] = addr + 4;
		ok = 1;
	/* BL, BLX (Off) */
	} else if (ARM_INSN_MATCH(BLX1, insn)) {
		memcpy(tramp, blx_off_insn_execbuf, KPROBES_TRAMP_LEN);
		tramp[0] |= 0xe0000000;
		tramp[1] |= 0xe0000000;
		tramp[KPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
		tramp[6] = get_addr_b(insn, addr) +
			   2 * (insn & 01000000) + 1; /* jump to thumb */
		tramp[7] = addr + 4;
		ok = 1;
	/* BL */
	} else if (ARM_INSN_MATCH(BL, insn)) {
		memcpy(tramp, blx_off_insn_execbuf, KPROBES_TRAMP_LEN);
		tramp[0] |= insn & 0xf0000000;
		tramp[1] |= insn & 0xf0000000;
		tramp[KPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
		tramp[6] = get_addr_b(insn, addr);
		tramp[7] = addr + 4;
		ok = 1;
	}

	return ok;
}

int arch_make_trampoline_arm(unsigned long addr, unsigned long insn,
			     unsigned long *tramp)
{
	int ret, uregs, pc_dep;

	if (addr & 0x03) {
		printk("Error in %s at %d: attempt to register uprobe "
		       "at an unaligned address\n", __FILE__, __LINE__);
		return -EINVAL;
	}

	ret = arch_check_insn_arm(insn);
	if (ret)
		return ret;

	if (make_branch_tarmpoline(addr, insn, tramp))
		return 0;

	uregs = pc_dep = 0;
	/* Rm */
	if (ARM_INSN_MATCH(CLZ, insn)) {
		uregs = 0xa;
		if (ARM_INSN_REG_RM(insn) == 15)
			pc_dep = 1;
	/* Rn, Rm ,Rd */
	} else if (ARM_INSN_MATCH(DPIS, insn) || ARM_INSN_MATCH(LRO, insn) ||
	    ARM_INSN_MATCH(SRO, insn)) {
		uregs = 0xb;
		if ((ARM_INSN_REG_RN(insn) == 15) ||
		    (ARM_INSN_REG_RM(insn) == 15) ||
		    (ARM_INSN_MATCH(SRO, insn) &&
		     (ARM_INSN_REG_RD(insn) == 15))) {
			pc_dep = 1;
		}
	/* Rn ,Rd */
	} else if (ARM_INSN_MATCH(DPI, insn) || ARM_INSN_MATCH(LIO, insn) ||
		   ARM_INSN_MATCH(SIO, insn)) {
		uregs = 0x3;
		if ((ARM_INSN_REG_RN(insn) == 15) ||
		    (ARM_INSN_MATCH(SIO, insn) &&
		    (ARM_INSN_REG_RD(insn) == 15))) {
			pc_dep = 1;
		}
	/* Rn, Rm, Rs */
	} else if (ARM_INSN_MATCH(DPRS, insn)) {
		uregs = 0xd;
		if ((ARM_INSN_REG_RN(insn) == 15) ||
		    (ARM_INSN_REG_RM(insn) == 15) ||
		    (ARM_INSN_REG_RS(insn) == 15)) {
			pc_dep = 1;
		}
	/* register list */
	} else if (ARM_INSN_MATCH(SM, insn)) {
		uregs = 0x10;
		if (ARM_INSN_REG_MR(insn, 15)) {
			pc_dep = 1;
		}
	}

	/* check instructions that can write result to SP and uses PC */
	if (pc_dep && (ARM_INSN_REG_RD(insn) == 13)) {
		printk("Error in %s at %d: instruction check failed (arm)\n",
		       __FILE__, __LINE__);
		return -EFAULT;
	}

	if (unlikely(uregs && pc_dep)) {
		memcpy(tramp, pc_dep_insn_execbuf, KPROBES_TRAMP_LEN);
		if (prep_pc_dep_insn_execbuf(tramp, insn, uregs) != 0) {
			printk("Error in %s at %d: failed "
			       "to prepare exec buffer for insn %lx!",
			       __FILE__, __LINE__, insn);
			return -EINVAL;
		}

		tramp[6] = addr + 8;
	} else {
		memcpy(tramp, gen_insn_execbuf, KPROBES_TRAMP_LEN);
		tramp[KPROBES_TRAMP_INSN_IDX] = insn;
	}

	/* TODO: remove for kprobe */
	tramp[KPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;
	tramp[7] = addr + 4;

	return 0;
}
EXPORT_SYMBOL_GPL(arch_make_trampoline_arm);

int arch_prepare_kprobe(struct kprobe *p, struct slot_manager *sm)
{
	unsigned long addr = (unsigned long)p->addr;
	unsigned long insn = p->opcode = *p->addr;
	unsigned long *tramp;
	int ret;

	tramp = alloc_insn_slot(sm);
	if (tramp == NULL)
		return -ENOMEM;

	ret = arch_make_trampoline_arm(addr, insn, tramp);
	if (ret) {
		free_insn_slot(sm, tramp);
		return ret;
	}

	flush_icache_range((unsigned long)tramp,
			   (unsigned long)tramp + KPROBES_TRAMP_LEN);

	p->ainsn.insn = tramp;

	return 0;
}

void prepare_singlestep(struct kprobe *p, struct pt_regs *regs)
{
	int cpu = smp_processor_id();

	if (p->ss_addr[cpu]) {
		regs->ARM_pc = (unsigned long)p->ss_addr[cpu];
		p->ss_addr[cpu] = NULL;
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
		p->ss_addr[smp_processor_id()] = (void *)
						 pre_entry(jp->priv_arg, regs);
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





/*
 ******************************************************************************
 *                                   kjumper                                  *
 ******************************************************************************
 */
struct kj_cb_data {
	unsigned long ret_addr;

	struct pt_regs regs;

	jumper_cb_t cb;
	char data[0];
};

static struct kj_cb_data * __used kjump_handler(struct kj_cb_data *data)
{
	/* call callback */
	data->cb(data->data);

	return data;
}

void kjump_trampoline(void);
__asm(
	"kjump_trampoline:		\n"

	"mov	r0, r10			\n"
	"bl	kjump_handler		\n"
	"nop				\n"	/* for kjump_kprobe */
);

unsigned long get_kjump_addr(void)
{
	return (unsigned long)&kjump_trampoline;
}
EXPORT_SYMBOL_GPL(get_kjump_addr);

int set_kjump_cb(unsigned long ret_addr, struct pt_regs *regs,
		 jumper_cb_t cb, void *data, size_t size)
{
	struct kj_cb_data *cb_data;

	cb_data = kmalloc(sizeof(*cb_data) + size, GFP_ATOMIC);
	if (cb_data == NULL)
		return -ENOMEM;

	cb_data->ret_addr = ret_addr;
	cb_data->cb = cb;

	/* save regs */
	memcpy(&cb_data->regs, regs, sizeof(*regs));

	memcpy(cb_data->data, data, size);

	/* save cb_data to r10 */
	regs->ARM_r10 = (long)cb_data;

	return 0;
}
EXPORT_SYMBOL_GPL(set_kjump_cb);

static int kjump_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kj_cb_data *data = (struct kj_cb_data *)regs->ARM_r0;

	/* restore regs */
	memcpy(regs, &data->regs, sizeof(*regs));
	p->ss_addr[smp_processor_id()] = (void *)data->ret_addr;

	/* FIXME: potential memory leak, when process kill */
	kfree(data);

	return 0;
}

static struct kprobe kjump_kprobe = {
	.pre_handler = kjump_pre_handler,
	.addr = (unsigned long *)&kjump_trampoline + 2,	/* nop */
};

static int kjump_init(void)
{
	int ret;

	ret = dbi_register_kprobe(&kjump_kprobe);
	if (ret)
		printk("ERROR: kjump_init(), ret=%d\n", ret);

	return ret;
}

static void kjump_exit(void)
{
	dbi_unregister_kprobe(&kjump_kprobe);
}





/*
 ******************************************************************************
 *                                   jumper                                   *
 ******************************************************************************
 */
struct cb_data {
	unsigned long ret_addr;
	unsigned long r0;

	jumper_cb_t cb;
	char data[0];
};

static unsigned long __used get_r0(struct cb_data *data)
{
	return data->r0;
}

static unsigned long __used jump_handler(struct cb_data *data)
{
	unsigned long ret_addr = data->ret_addr;

	/* call callback */
	data->cb(data->data);

	/* FIXME: potential memory leak, when process kill */
	kfree(data);

	return ret_addr;
}

/* FIXME: restore condition flags */
void jump_trampoline(void);
__asm(
	"jump_trampoline:		\n"

	"push	{r0 - r12}		\n"
	"mov	r1, r0			\n"	/* data --> r1 */
	"bl	get_r0			\n"
	"str	r0, [sp]		\n"	/* restore r0 */
	"mov	r0, r1			\n"	/* data --> r0 */
	"bl	jump_handler		\n"
	"mov	lr, r0			\n"
	"pop	{r0 - r12}		\n"
	"bx	lr			\n"
);

unsigned long get_jump_addr(void)
{
	return (unsigned long)&jump_trampoline;
}
EXPORT_SYMBOL_GPL(get_jump_addr);

int set_jump_cb(unsigned long ret_addr, struct pt_regs *regs,
		jumper_cb_t cb, void *data, size_t size)
{
	struct cb_data *cb_data;

	cb_data = kmalloc(sizeof(*cb_data) + size, GFP_ATOMIC);

	/* save data */
	cb_data->ret_addr = ret_addr;
	cb_data->cb = cb;
	cb_data->r0 = regs->ARM_r0;
	memcpy(cb_data->data, data, size);

	/* save cb_data to r0 */
	regs->ARM_r0 = (long)cb_data;

	return 0;
}
EXPORT_SYMBOL_GPL(set_jump_cb);





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
	int ret;

	// Register hooks (kprobe_handler)
	__swap_register_undef_hook = (void *)swap_ksyms("register_undef_hook");
	if (__swap_register_undef_hook == NULL) {
		printk("no register_undef_hook symbol found!\n");
                return -1;
        }

        // Unregister hooks (kprobe_handler)
	__swap_unregister_undef_hook = (void *)swap_ksyms("unregister_undef_hook");
	if (__swap_unregister_undef_hook == NULL) {
                printk("no unregister_undef_hook symbol found!\n");
                return -1;
        }

	swap_register_undef_hook(&undef_ho_k);

	ret = kjump_init();
	if (ret) {
		swap_unregister_undef_hook(&undef_ho_k);
		return ret;
	}

	return 0;
}

void arch_exit_kprobes(void)
{
	kjump_exit();
	swap_unregister_undef_hook(&undef_ho_k);
}

/* export symbol for trampoline_arm.h */
EXPORT_SYMBOL_GPL(gen_insn_execbuf);
EXPORT_SYMBOL_GPL(pc_dep_insn_execbuf);
EXPORT_SYMBOL_GPL(b_r_insn_execbuf);
EXPORT_SYMBOL_GPL(b_cond_insn_execbuf);
EXPORT_SYMBOL_GPL(blx_off_insn_execbuf);
