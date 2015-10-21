/**
 * uprobe/arch/asm-x86/swap_uprobes.c
 * @author Alexey Gerenkov <a.gerenkov@samsung.com> User-Space Probes initial
 * implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * @author Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for
 * separating core and arch parts
 *
 * @section LICENSE
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
 * @section COPYRIGHT
 *
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * @section DESCRIPTION
 *
 * Arch-dependent uprobe interface implementation for x86.
 */


#include <linux/kdebug.h>

#include <kprobe/swap_slots.h>
#include <uprobe/swap_uprobes.h>

#include "swap_uprobes.h"


/**
 * @struct uprobe_ctlblk
 * @brief Uprobe control block
 */
struct uprobe_ctlblk {
	unsigned long flags;            /**< Flags */
	struct uprobe *p;               /**< Pointer to the uprobe */
};

static unsigned long trampoline_addr(struct uprobe *up)
{
	return (unsigned long)(up->ainsn.insn +
			       UPROBES_TRAMP_RET_BREAK_IDX);
}

unsigned long arch_tramp_by_ri(struct uretprobe_instance *ri)
{
	return trampoline_addr(&ri->rp->up);
}

static struct uprobe_ctlblk *current_ucb(void)
{
	/* FIXME hardcoded offset */
	return (struct uprobe_ctlblk *)(end_of_stack(current) + 20);
}

static struct uprobe *get_current_probe(void)
{
	return current_ucb()->p;
}

static void set_current_probe(struct uprobe *p)
{
	current_ucb()->p = p;
}

static void save_current_flags(struct pt_regs *regs)
{
	current_ucb()->flags = regs->flags;
}

static void restore_current_flags(struct pt_regs *regs, unsigned long flags)
{
	regs->flags &= ~IF_MASK;
	regs->flags |= flags & IF_MASK;
}

/**
 * @brief Prepares uprobe for x86.
 *
 * @param up Pointer to the uprobe.
 * @return 0 on success,\n
 * -1 on error.
 */
int arch_prepare_uprobe(struct uprobe *p)
{
	struct task_struct *task = p->task;
	u8 *tramp = p->atramp.tramp;
	enum { call_relative_opcode = 0xe8 };

	if (!read_proc_vm_atomic(task, (unsigned long)p->addr,
				 tramp, MAX_INSN_SIZE)) {
		printk(KERN_ERR "failed to read memory %p!\n", p->addr);
		return -EINVAL;
	}
	/* TODO: this is a workaround */
	if (tramp[0] == call_relative_opcode) {
		printk(KERN_INFO "cannot install probe: 1st instruction is call\n");
		return -EINVAL;
	}

	tramp[UPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;

	/* TODO: remove dual info */
	p->opcode = tramp[0];

	p->ainsn.boostable = swap_can_boost(tramp) ? 0 : -1;

	p->ainsn.insn = swap_slot_alloc(p->sm);
	if (p->ainsn.insn == NULL) {
		printk(KERN_ERR "trampoline out of memory\n");
		return -ENOMEM;
	}

	if (!write_proc_vm_atomic(task, (unsigned long)p->ainsn.insn,
				  tramp, sizeof(p->atramp.tramp))) {
		swap_slot_free(p->sm, p->ainsn.insn);
		printk(KERN_INFO "failed to write memory %p!\n", tramp);
		return -EINVAL;
	}

	/* for uretprobe */
	add_uprobe_table(p);

	return 0;
}

/**
 * @brief Jump pre-handler.
 *
 * @param p Pointer to the uprobe.
 * @param regs Pointer to CPU register data.
 * @return 0.
 */
int setjmp_upre_handler(struct uprobe *p, struct pt_regs *regs)
{
	struct ujprobe *jp = container_of(p, struct ujprobe, up);
	uprobe_pre_entry_handler_t pre_entry =
		(uprobe_pre_entry_handler_t)jp->pre_entry;
	entry_point_t entry = (entry_point_t)jp->entry;
	unsigned long args[6];

	/* FIXME some user space apps crash if we clean interrupt bit */
	/* regs->EREG(flags) &= ~IF_MASK; */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
	trace_hardirqs_off();
#endif

	/* read first 6 args from stack */
	if (!read_proc_vm_atomic(current, regs->EREG(sp) + 4,
				 args, sizeof(args)))
		printk(KERN_WARNING
		       "failed to read user space func arguments %lx!\n",
		       regs->sp + 4);

	if (pre_entry)
		p->ss_addr[smp_processor_id()] = (uprobe_opcode_t *)
						 pre_entry(jp->priv_arg, regs);

	if (entry)
		entry(args[0], args[1], args[2], args[3], args[4], args[5]);
	else
		arch_ujprobe_return();

	return 0;
}

/**
 * @brief Prepares uretprobe for x86.
 *
 * @param ri Pointer to the uretprobe instance.
 * @param regs Pointer to CPU register data.
 * @return Void.
 */
int arch_prepare_uretprobe(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	/* Replace the return addr with trampoline addr */
	unsigned long ra = trampoline_addr(&ri->rp->up);
	unsigned long ret_addr;
	ri->sp = (kprobe_opcode_t *)regs->sp;

	if (get_user(ret_addr, (unsigned long *)regs->sp)) {
		pr_err("failed to read user space func ra %lx addr=%p!\n",
		       regs->sp, ri->rp->up.addr);
		return -EINVAL;
	}

	if (put_user(ra, (unsigned long *)regs->sp)) {
		pr_err("failed to write user space func ra %lx!\n", regs->sp);
		return -EINVAL;
	}

	ri->ret_addr = (uprobe_opcode_t *)ret_addr;

	return 0;
}

static bool get_long(struct task_struct *task,
		     unsigned long vaddr, unsigned long *val)
{
	return sizeof(*val) != read_proc_vm_atomic(task, vaddr,
						   val, sizeof(*val));
}

static bool put_long(struct task_struct *task,
		     unsigned long vaddr, unsigned long *val)
{
	return sizeof(*val) != write_proc_vm_atomic(task, vaddr,
						    val, sizeof(*val));
}

/**
 * @brief Disarms uretprobe on x86 arch.
 *
 * @param ri Pointer to the uretprobe instance.
 * @param task Pointer to the task for which the probe.
 * @return 0 on success,\n
 * negative error code on error.
 */
int arch_disarm_urp_inst(struct uretprobe_instance *ri,
			 struct task_struct *task, unsigned long tr)
{
	unsigned long ret_addr;
	unsigned long sp = (unsigned long)ri->sp;
	unsigned long tramp_addr;

	if (tr == 0)
		tramp_addr = arch_tramp_by_ri(ri);
	else
		tramp_addr = tr; /* ri - invalid */

	if (get_long(task, sp, &ret_addr)) {
		printk(KERN_INFO "---> %s (%d/%d): failed to read stack from %08lx\n",
		       task->comm, task->tgid, task->pid, sp);
		return -EFAULT;
	}

	if (tramp_addr == ret_addr) {
		if (put_long(task, sp, (unsigned long *)&ri->ret_addr)) {
			printk(KERN_INFO "---> %s (%d/%d): failed to write "
			       "orig_ret_addr to %08lx",
			       task->comm, task->tgid, task->pid, sp);
			return -EFAULT;
		}
	} else {
		printk(KERN_INFO "---> %s (%d/%d): trampoline NOT found at sp = %08lx\n",
		       task->comm, task->tgid, task->pid, sp);
		return -ENOENT;
	}

	return 0;
}

/**
 * @brief Gets trampoline address.
 *
 * @param p Pointer to the uprobe.
 * @param regs Pointer to CPU register data.
 * @return Trampoline address.
 */
unsigned long arch_get_trampoline_addr(struct uprobe *p, struct pt_regs *regs)
{
	return trampoline_addr(p);
}

/**
 * @brief Restores return address.
 *
 * @param orig_ret_addr Original return address.
 * @param regs Pointer to CPU register data.
 * @return Void.
 */
void arch_set_orig_ret_addr(unsigned long orig_ret_addr, struct pt_regs *regs)
{
	regs->EREG(ip) = orig_ret_addr;
}

/**
 * @brief Removes uprobe.
 *
 * @param up Pointer to the target uprobe.
 * @return Void.
 */
void arch_remove_uprobe(struct uprobe *p)
{
	swap_slot_free(p->sm, p->ainsn.insn);
}

int arch_arm_uprobe(struct uprobe *p)
{
	int ret;
	uprobe_opcode_t insn = BREAKPOINT_INSTRUCTION;
	unsigned long vaddr = (unsigned long)p->addr;

	ret = write_proc_vm_atomic(p->task, vaddr, &insn, sizeof(insn));
	if (!ret) {
		pr_err("arch_arm_uprobe: failed to write memory tgid=%u vaddr=%08lx\n",
		       p->task->tgid, vaddr);

		return -EACCES;
	}

	return 0;
}

void arch_disarm_uprobe(struct uprobe *p, struct task_struct *task)
{
	int ret;
	unsigned long vaddr = (unsigned long)p->addr;

	ret = write_proc_vm_atomic(task, vaddr, &p->opcode, sizeof(p->opcode));
	if (!ret) {
		pr_err("arch_disarm_uprobe: failed to write memory tgid=%u, vaddr=%08lx\n",
		       task->tgid, vaddr);
	}
}

static void set_user_jmp_op(void *from, void *to)
{
	struct __arch_jmp_op {
		char op;
		long raddr;
	} __packed jop;

	jop.raddr = (long)(to) - ((long)(from) + 5);
	jop.op = RELATIVEJUMP_INSTRUCTION;

	if (put_user(jop.op, (char *)from) ||
	    put_user(jop.raddr, (long *)(from + 1)))
		pr_err("failed to write jump opcode to user space %p\n", from);
}

static void resume_execution(struct uprobe *p,
			     struct pt_regs *regs,
			     unsigned long flags)
{
	unsigned long *tos, tos_dword = 0;
	unsigned long copy_eip = (unsigned long)p->ainsn.insn;
	unsigned long orig_eip = (unsigned long)p->addr;
	uprobe_opcode_t insns[2];

	regs->EREG(flags) &= ~TF_MASK;

	tos = (unsigned long *)&tos_dword;
	if (get_user(tos_dword, (unsigned long *)regs->sp)) {
		pr_err("failed to read from user space sp=%lx!\n", regs->sp);
		return;
	}

	if (get_user(*(unsigned short *)insns, (unsigned short *)p->ainsn.insn)) {
		pr_err("failed to read first 2 opcodes %p!\n", p->ainsn.insn);
		return;
	}

	switch (insns[0]) {
	case 0x9c: /* pushfl */
		*tos &= ~(TF_MASK | IF_MASK);
		*tos |= flags & (TF_MASK | IF_MASK);
		break;
	case 0xc2: /* iret/ret/lret */
	case 0xc3:
	case 0xca:
	case 0xcb:
	case 0xcf:
	case 0xea: /* jmp absolute -- eip is correct */
		/* eip is already adjusted, no more changes required */
		p->ainsn.boostable = 1;
		goto no_change;
	case 0xe8: /* call relative - Fix return addr */
		*tos = orig_eip + (*tos - copy_eip);
		break;
	case 0x9a: /* call absolute -- same as call absolute, indirect */
		*tos = orig_eip + (*tos - copy_eip);

		if (put_user(tos_dword, (unsigned long *)regs->sp)) {
			pr_err("failed to write dword to sp=%lx\n", regs->sp);
			return;
		}

		goto no_change;
	case 0xff:
		if ((insns[1] & 0x30) == 0x10) {
			/*
			 * call absolute, indirect
			 * Fix return addr; eip is correct.
			 * But this is not boostable
			 */
			*tos = orig_eip + (*tos - copy_eip);

			if (put_user(tos_dword, (unsigned long *)regs->sp)) {
				pr_err("failed to write dword to sp=%lx\n", regs->sp);
				return;
			}

			goto no_change;
		} else if (((insns[1] & 0x31) == 0x20) || /* jmp near, absolute
							   * indirect */
			   ((insns[1] & 0x31) == 0x21)) {
			/* jmp far, absolute indirect */
			/* eip is correct. And this is boostable */
			p->ainsn.boostable = 1;
			goto no_change;
		}
	case 0xf3:
		if (insns[1] == 0xc3)
			/* repz ret special handling: no more changes */
			goto no_change;
		break;
	default:
		break;
	}

	if (put_user(tos_dword, (unsigned long *)regs->sp)) {
		pr_err("failed to write dword to sp=%lx\n", regs->sp);
		return;
	}

	if (p->ainsn.boostable == 0) {
		if ((regs->EREG(ip) > copy_eip) && (regs->EREG(ip) - copy_eip) +
		    5 < MAX_INSN_SIZE) {
			/*
			 * These instructions can be executed directly if it
			 * jumps back to correct address.
			 */
			set_user_jmp_op((void *) regs->EREG(ip),
					(void *)orig_eip +
					(regs->EREG(ip) - copy_eip));
			p->ainsn.boostable = 1;
		} else {
			p->ainsn.boostable = -1;
		}
	}

	regs->EREG(ip) = orig_eip + (regs->EREG(ip) - copy_eip);

no_change:
	return;
}

static bool prepare_ss_addr(struct uprobe *p, struct pt_regs *regs)
{
	unsigned long *ss_addr = (long *)&p->ss_addr[smp_processor_id()];

	if (*ss_addr) {
		regs->ip = *ss_addr;
		*ss_addr = 0;
		return true;
	} else {
		regs->ip = (unsigned long)p->ainsn.insn;
		return false;
	}
}

static void prepare_ss(struct pt_regs *regs)
{
	/* set single step mode */
	regs->flags |= TF_MASK;
	regs->flags &= ~IF_MASK;
}

static int uprobe_handler(struct pt_regs *regs)
{
	struct uprobe *p;
	uprobe_opcode_t *addr;
	struct task_struct *task = current;
	pid_t tgid = task->tgid;

	save_current_flags(regs);

	addr = (uprobe_opcode_t *)(regs->EREG(ip) - sizeof(uprobe_opcode_t));
	p = get_uprobe(addr, tgid);

	if (p == NULL) {
		void *tramp_addr = (void *)addr - UPROBES_TRAMP_RET_BREAK_IDX;

		p = get_uprobe_by_insn_slot(tramp_addr, tgid, regs);
		if (p == NULL) {
			printk(KERN_INFO "no_uprobe\n");
			return 0;
		}

		trampoline_uprobe_handler(p, regs);
		return 1;
	} else {
		if (!p->pre_handler || !p->pre_handler(p, regs)) {
			if (p->ainsn.boostable == 1 && !p->post_handler) {
				prepare_ss_addr(p, regs);
				return 1;
			}

			if (prepare_ss_addr(p, regs) == false) {
				set_current_probe(p);
				prepare_ss(regs);
			}
		}
	}

	return 1;
}

static int post_uprobe_handler(struct pt_regs *regs)
{
	struct uprobe *p = get_current_probe();
	unsigned long flags = current_ucb()->flags;

	if (p == NULL) {
		printk("task[%u %u %s] current uprobe is not found\n",
		       current->tgid, current->pid, current->comm);
		return 0;
	}

	resume_execution(p, regs, flags);
	restore_current_flags(regs, flags);

	/* clean stack */
	current_ucb()->p = 0;
	current_ucb()->flags = 0;

	return 1;
}

static int uprobe_exceptions_notify(struct notifier_block *self,
				    unsigned long val, void *data)
{
	struct die_args *args = (struct die_args *)data;
	int ret = NOTIFY_DONE;

	if (args->regs == NULL || !user_mode_vm(args->regs))
		return ret;

	switch (val) {
#ifdef CONFIG_KPROBES
	case DIE_INT3:
#else
	case DIE_TRAP:
#endif
		if (uprobe_handler(args->regs))
			ret = NOTIFY_STOP;
		break;
	case DIE_DEBUG:
		if (post_uprobe_handler(args->regs))
			ret = NOTIFY_STOP;
		break;
	default:
		break;
	}

	return ret;
}

static struct notifier_block uprobe_exceptions_nb = {
	.notifier_call = uprobe_exceptions_notify,
	.priority = INT_MAX
};

/**
 * @brief Registers notify.
 *
 * @return register_die_notifier result.
 */
int swap_arch_init_uprobes(void)
{
	return register_die_notifier(&uprobe_exceptions_nb);
}

/**
 * @brief Unregisters notify.
 *
 * @return Void.
 */
void swap_arch_exit_uprobes(void)
{
	unregister_die_notifier(&uprobe_exceptions_nb);
}

