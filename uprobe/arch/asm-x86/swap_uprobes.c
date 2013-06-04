#include <linux/kdebug.h>
#include <asm/dbi_kprobes.h>
#include <swap_uprobes.h>
#include <asm/swap_uprobes.h>
#include <dbi_insn_slots.h>

struct uprobe_ctlblk {
        unsigned long flags;
        struct kprobe *p;
};

static DEFINE_PER_CPU(struct uprobe_ctlblk, ucb) = { 0, NULL };

int arch_prepare_uprobe(struct uprobe *up, struct hlist_head *page_list)
{
	int ret = 0;
	struct kprobe *p = &up->kp;
	struct task_struct *task = up->task;
	kprobe_opcode_t insns[UPROBES_TRAMP_LEN];

	if (!ret) {
		kprobe_opcode_t insn[MAX_INSN_SIZE];
		struct arch_specific_insn ainsn;

		if (!read_proc_vm_atomic(task, (unsigned long)p->addr, &insn, MAX_INSN_SIZE * sizeof(kprobe_opcode_t)))
			panic("failed to read memory %p!\n", p->addr);

		ainsn.insn = insn;
		ret = arch_check_insn(&ainsn);
		if (!ret) {
			p->opcode = insn[0];
			p->ainsn.insn = alloc_insn_slot(up->sm);
			if (!p->ainsn.insn)
				return -ENOMEM;

			if (can_boost(insn))
				p->ainsn.boostable = 0;
			else
				p->ainsn.boostable = -1;

			memcpy(&insns[UPROBES_TRAMP_INSN_IDX], insn, MAX_INSN_SIZE*sizeof(kprobe_opcode_t));
			insns[UPROBES_TRAMP_RET_BREAK_IDX] = BREAKPOINT_INSTRUCTION;

			if (!write_proc_vm_atomic(task, (unsigned long)p->ainsn.insn, insns, sizeof(insns))) {
				free_insn_slot(up->sm, p->ainsn.insn);
				panic("failed to write memory %p!\n", p->ainsn.insn);
				return -EINVAL;
			}
		}
	}

	return ret;
}

int setjmp_upre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct uprobe *up = container_of(p, struct uprobe, kp);
	struct ujprobe *jp = container_of(up, struct ujprobe, up);
	kprobe_pre_entry_handler_t pre_entry = (kprobe_pre_entry_handler_t)jp->pre_entry;
	entry_point_t entry = (entry_point_t)jp->entry;
	unsigned long addr, args[6];

	/* FIXME some user space apps crash if we clean interrupt bit */
	//regs->EREG(flags) &= ~IF_MASK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
	trace_hardirqs_off();
#endif

	/* read first 6 args from stack */
	if (!read_proc_vm_atomic(current, regs->EREG(sp) + 4, args, sizeof(args)))
		panic("failed to read user space func arguments %lx!\n", regs->EREG(sp) + 4);

	if (pre_entry)
		p->ss_addr = pre_entry(jp->priv_arg, regs);

	if (entry)
		entry(args[0], args[1], args[2], args[3], args[4], args[5]);
	else
		arch_ujprobe_return();

	return 0;
}

void arch_prepare_uretprobe(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	/* Replace the return addr with trampoline addr */
	unsigned long ra = (unsigned long)(ri->rp->up.kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);

	if (!read_proc_vm_atomic(current, regs->EREG(sp), &(ri->ret_addr), sizeof(ri->ret_addr)))
		panic("failed to read user space func ra %lx!\n", regs->EREG(sp));

	if (!write_proc_vm_atomic(current, regs->EREG(sp), &ra, sizeof(ra)))
		panic("failed to write user space func ra %lx!\n", regs->EREG(sp));
}

unsigned long arch_get_trampoline_addr(struct kprobe *p, struct pt_regs *regs)
{
	return (unsigned long)(p->ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
}

void arch_set_orig_ret_addr(unsigned long orig_ret_addr, struct pt_regs *regs)
{
	regs->EREG(ip) = orig_ret_addr;
}

static void set_user_jmp_op(void *from, void *to)
{
	struct __arch_jmp_op
	{
		char op;
		long raddr;
	} __attribute__ ((packed)) jop;

	jop.raddr = (long)(to) - ((long)(from) + 5);
	jop.op = RELATIVEJUMP_INSTRUCTION;

	if (!write_proc_vm_atomic(current, (unsigned long)from, &jop, sizeof(jop)))
		panic("failed to write jump opcode to user space %p!\n", from);
}

static void resume_execution(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	unsigned long *tos, tos_dword = 0;
	unsigned long copy_eip = (unsigned long)p->ainsn.insn;
	unsigned long orig_eip = (unsigned long)p->addr;
	kprobe_opcode_t insns[2];

	regs->EREG(flags) &= ~TF_MASK;

	tos = (unsigned long *)&tos_dword;
	if (!read_proc_vm_atomic(current, regs->EREG(sp), &tos_dword, sizeof(tos_dword)))
		panic("failed to read dword from top of the user space stack %lx!\n", regs->EREG(sp));

	if (!read_proc_vm_atomic(current, (unsigned long)p->ainsn.insn, insns, 2 * sizeof(kprobe_opcode_t)))
		panic("failed to read first 2 opcodes of instruction copy from user space %p!\n", p->ainsn.insn);

	switch (insns[0]) {
		case 0x9c:		/* pushfl */
			*tos &= ~(TF_MASK | IF_MASK);
			*tos |= flags;
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

			if (!write_proc_vm_atomic(current, regs->EREG (sp), &tos_dword, sizeof(tos_dword)))
				panic("failed to write dword to top of the user space stack %lx!\n", regs->EREG (sp));

			goto no_change;
		case 0xff:
			if ((insns[1] & 0x30) == 0x10) {
				/*
				 * call absolute, indirect
				 * Fix return addr; eip is correct.
				 * But this is not boostable
				 */
				*tos = orig_eip + (*tos - copy_eip);

				if (!write_proc_vm_atomic(current, regs->EREG(sp), &tos_dword, sizeof(tos_dword)))
					panic("failed to write dword to top of the user space stack %lx!\n", regs->EREG(sp));

				goto no_change;
			} else if (((insns[1] & 0x31) == 0x20) || /* jmp near, absolute indirect */
				   ((insns[1] & 0x31) == 0x21)) {
				/* jmp far, absolute indirect */
				/* eip is correct. And this is boostable */
				p->ainsn.boostable = 1;
				goto no_change;
			}
		default:
			break;
	}

	if (!write_proc_vm_atomic(current, regs->EREG(sp), &tos_dword, sizeof(tos_dword)))
		panic("failed to write dword to top of the user space stack %lx!\n", regs->EREG(sp));

	if (p->ainsn.boostable == 0) {
		if ((regs->EREG(ip) > copy_eip) && (regs->EREG(ip) - copy_eip) + 5 < MAX_INSN_SIZE) {
			/*
			 * These instructions can be executed directly if it
			 * jumps back to correct address.
			 */
			set_user_jmp_op((void *) regs->EREG(ip), (void *)orig_eip + (regs->EREG(ip) - copy_eip));
			p->ainsn.boostable = 1;
		} else {
			p->ainsn.boostable = -1;
		}
	}

	regs->EREG(ip) = orig_eip + (regs->EREG(ip) - copy_eip);

no_change:
	return;
}

static int uprobe_handler(struct pt_regs *regs)
{
	struct kprobe *p;
	kprobe_opcode_t *addr;
	struct task_struct *task = current;
	pid_t tgid = task->tgid;

	addr = (kprobe_opcode_t *)(regs->EREG(ip) - sizeof(kprobe_opcode_t));
	p = get_ukprobe(addr, tgid);

	if (p == NULL) {
		p = get_ukprobe_by_insn_slot(addr, tgid, regs);

		if (p == NULL) {
			printk("no_uprobe\n");
			return 0;
		}

		trampoline_uprobe_handler(p, regs);
	} else {
		if (!p->pre_handler || !p->pre_handler(p, regs))
			prepare_singlestep(p, regs);
	}

	__get_cpu_var(ucb).p = p;
	__get_cpu_var(ucb).flags = (regs->EREG(flags) & (TF_MASK | IF_MASK));

	return 1;
}

static int post_uprobe_handler(struct pt_regs *regs)
{
	struct kprobe *p = __get_cpu_var(ucb).p;
	unsigned long flags = __get_cpu_var(ucb).flags;

	resume_execution(p, regs, flags);

	return 1;
}

static int uprobe_exceptions_notify(struct notifier_block *self, unsigned long val, void *data)
{
	struct die_args *args = (struct die_args *)data;
	int ret = NOTIFY_DONE;

	if (args->regs && !user_mode_vm(args->regs))
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

int swap_arch_init_uprobes(void)
{
	return register_die_notifier(&uprobe_exceptions_nb);
}

void swap_arch_exit_uprobes(void)
{
	unregister_die_notifier(&uprobe_exceptions_nb);
}

