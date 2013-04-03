#ifndef _SRC_ASM_X86_KPROBES_H
#define _SRC_ASM_X86_KPROBES_H

/*
 *  Kernel Probes (KProbes)
 *  include/linux/kprobes.h
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
 *  modules/kprobe/arch/asm-x86/dbi_kprobes.h
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
 * Copyright (C) Samsung Electronics, 2006-2013
 *
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation;
 *              Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>:
 *              redesign module for separating core and arch parts
 * 2010-2012    Dmitry Kovalenko <d.kovalenko@samsung.com>,
 *              Nikita Kalyazin <n.kalyazin@samsung.com>
 *              improvement and bugs fixing
 * 2010-2011    Alexander Shirshikov
 *              improvement and bugs fixing
 * 2011-2012    Stanislav Andreev <s.andreev@samsung.com>
 *              improvement and bugs fixing
 * 2012         Vitaliy Cherepanov <v.chereapanov@samsung.com>
 *              improvement and bugs fixing
 * 2012-2013    Vasiliy Ulyanov <v.ulyanov@samsung.com>,
 *              Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *              improvement and bugs fixing
 */

#include "../../dbi_kprobes_deps.h"
#include "../dbi_kprobes.h"

typedef u8 kprobe_opcode_t;

#define BREAKPOINT_INSTRUCTION          0xcc
#define RELATIVEJUMP_INSTRUCTION        0xe9

#define MAX_INSN_SIZE                   16
#define MAX_STACK_SIZE                  64

#define MIN_STACK_SIZE(ADDR)   (((MAX_STACK_SIZE) <			  \
			(((unsigned long)current_thread_info())  \
			 + THREAD_SIZE - (ADDR)))		  \
		? (MAX_STACK_SIZE)			  \
		: (((unsigned long)current_thread_info()) \
			+ THREAD_SIZE - (ADDR)))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

#define EREG(rg)                e##rg
#define XREG(rg)                x##rg
#define ORIG_EAX_REG            orig_eax

#else

#define EREG(rg)                rg
#define XREG(rg)                rg
#define ORIG_EAX_REG            orig_ax

#endif /*  LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25) */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
#define TF_MASK                         X86_EFLAGS_TF
#define IF_MASK	                        X86_EFLAGS_IF
#endif
#define UPROBES_TRAMP_LEN               (MAX_INSN_SIZE+sizeof(kprobe_opcode_t))
#define UPROBES_TRAMP_INSN_IDX		0
#define UPROBES_TRAMP_RET_BREAK_IDX     MAX_INSN_SIZE
#define KPROBES_TRAMP_LEN		MAX_INSN_SIZE
#define KPROBES_TRAMP_INSN_IDX          0

static inline unsigned long arch_get_task_pc(struct task_struct *p)
{
	return p->thread.ip;
}

static inline void arch_set_task_pc(struct task_struct *p, unsigned long val)
{
	p->thread.ip = val;
}

static inline struct pt_regs *dbi_get_syscall_uregs(unsigned long sp)
{
	return NULL; //FIXME currently not implemented for x86
}

static inline unsigned long dbi_get_stack_ptr(struct pt_regs *regs)
{
	return regs->EREG(sp);
}

static inline unsigned long dbi_get_instr_ptr(struct pt_regs *regs)
{
	return regs->EREG(ip);
}

static inline void dbi_set_instr_ptr(struct pt_regs *regs, unsigned long val)
{
	regs->EREG(ip) = val;
}

static inline unsigned long dbi_get_ret_addr(struct pt_regs *regs)
{
	unsigned long addr = 0;
	read_proc_vm_atomic(current, regs->EREG(sp), &addr, sizeof(addr));
	return addr;
}

static inline void dbi_set_ret_addr(struct pt_regs *regs, unsigned long val)
{
	write_proc_vm_atomic(current, regs->EREG(sp), &val, sizeof(val));
}

static inline unsigned long dbi_get_arg(struct pt_regs *regs, int num)
{
	unsigned long arg = 0;
	read_proc_vm_atomic(current, regs->EREG(sp) + (1 + num) * 4,
			&arg, sizeof(arg));
	return arg;
}

static inline void dbi_set_arg(struct pt_regs *regs, int num, unsigned long val)
{
	write_proc_vm_atomic(current, regs->EREG(sp) + (1 + num) * 4,
			&val, sizeof(val));
}

static inline int dbi_fp_backtrace(struct task_struct *task, unsigned long *buf,
		int max_cnt)
{
	int i = 0;
	struct pt_regs *regs;

	struct {
		unsigned long next;
		unsigned long raddr;
	} frame;


	regs = task_pt_regs(task);
	frame.next = regs->EREG(bp);
	frame.raddr = dbi_get_ret_addr(regs);

	while (frame.next && i < max_cnt) {
		if (read_proc_vm_atomic(task, frame.next, &frame, sizeof(frame))
				== sizeof(frame))
			buf[i++] = frame.raddr;
		else
			break;
	}

	return i;
}

extern int kprobe_exceptions_notify (struct notifier_block *self, unsigned long val, void *data);

struct prev_kprobe;

/* per-cpu kprobe control block */
struct kprobe_ctlblk {
	unsigned long kprobe_status;
	struct prev_kprobe prev_kprobe;
	struct pt_regs jprobe_saved_regs;
	unsigned long kprobe_old_eflags;
	unsigned long kprobe_saved_eflags;
	unsigned long *jprobe_saved_esp;
	kprobe_opcode_t jprobes_stack[MAX_STACK_SIZE];
};


int kprobe_fault_handler (struct pt_regs *regs, int trapnr);

void * trampoline_probe_handler_x86 (struct pt_regs *regs);

/* Architecture specific copy of original instruction */
struct arch_specific_insn {
	/* copy of the original instruction */
	kprobe_opcode_t *insn;
	/*
	 * If this flag is not 0, this kprobe can be boost when its
	 * post_handler and break_handler is not set.
	 */
	int boostable;
};

typedef kprobe_opcode_t (*entry_point_t) (unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);



#endif /* _SRC_ASM_X86_KPROBES_H */
