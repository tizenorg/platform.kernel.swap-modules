#ifndef _ARM_SWAP_UPROBES_H
#define _ARM_SWAP_UPROBES_H

struct kprobe;
struct pt_regs;
struct task_struct;

int arch_prepare_uprobe(struct kprobe *p, struct task_struct *task, int atomic);

int setjmp_upre_handler(struct kprobe *p, struct pt_regs *regs);
static inline int longjmp_break_uhandler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

int swap_arch_init_uprobes(void);
void swap_arch_exit_uprobes(void);

#endif /* _ARM_SWAP_UPROBES_H */
