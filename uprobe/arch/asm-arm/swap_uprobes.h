#ifndef _ARM_SWAP_UPROBES_H
#define _ARM_SWAP_UPROBES_H

struct kprobe;
struct pt_regs;
struct task_struct;


static inline void dbi_arch_uprobe_return(void)
{
}

int arch_prepare_uprobe(struct kprobe *p, struct task_struct *task, int atomic);

int setjmp_upre_handler(struct kprobe *p, struct pt_regs *regs);
static inline int longjmp_break_uhandler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

void arch_prepare_uretprobe_hl(struct kretprobe_instance *ri, struct pt_regs *regs);

int swap_arch_init_uprobes(void);
void swap_arch_exit_uprobes(void);

#endif /* _ARM_SWAP_UPROBES_H */
