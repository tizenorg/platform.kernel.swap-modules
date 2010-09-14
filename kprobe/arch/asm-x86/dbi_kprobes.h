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
 *

 */

#include "dbi_kprobe_deps.h"
#include "arch/dbi_kprobes.h"

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

static struct notifier_block kprobe_exceptions_nb = {
	.notifier_call = kprobe_exceptions_notify,
	.priority = INT_MAX
};

struct prev_kprobe {
	struct kprobe *kp;
	unsigned long status;
	unsigned long old_eflags;
	unsigned long saved_eflags;
};

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

extern int kprobe_exceptions_notify (struct notifier_block *self, unsigned long val, void *data);

void __kprobes resume_execution 
(struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb);

int __kprobes post_kprobe_handler (struct pt_regs *regs);

int __kprobes
kprobe_fault_handler (struct pt_regs *regs, int trapnr);

void *__kprobes trampoline_probe_handler_x86 (struct pt_regs *regs);

DECLARE_MOD_FUNC_DEP(module_alloc, void *, unsigned long size);
DECLARE_MOD_FUNC_DEP(module_free, void, struct module *mod, void *module_region);
DECLARE_MOD_FUNC_DEP(fixup_exception, int, struct pt_regs * regs);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26))
DECLARE_MOD_FUNC_DEP(text_poke, void, void *addr, unsigned char *opcode, int len);
#else
DECLARE_MOD_FUNC_DEP(text_poke, void *, void *addr, const void *opcode, size_t len);
#endif
DECLARE_MOD_FUNC_DEP(show_registers, void, struct pt_regs * regs);

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
