#ifndef _ARM_SWAP_UPROBES_H
#define _ARM_SWAP_UPROBES_H

struct kprobe;
struct pt_regs;
struct task_struct;


static inline void arch_ujprobe_return(void)
{
}

int arch_prepare_uprobe(struct uprobe *up, struct hlist_head *page_list);

int setjmp_upre_handler(struct kprobe *p, struct pt_regs *regs);
static inline int longjmp_break_uhandler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

int arch_opcode_analysis_uretprobe(kprobe_opcode_t opcode);
void arch_prepare_uretprobe(struct uretprobe_instance *ri, struct pt_regs *regs);

unsigned long arch_get_trampoline_addr(struct kprobe *p, struct pt_regs *regs);
void arch_set_orig_ret_addr(unsigned long orig_ret_addr, struct pt_regs *regs);

int swap_arch_init_uprobes(void);
void swap_arch_exit_uprobes(void);

#endif /* _ARM_SWAP_UPROBES_H */
