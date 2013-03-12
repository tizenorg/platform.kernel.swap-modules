#ifndef _DBI_ARCH_KPROBES_H
#define _DBI_ARCH_KPROBES_H

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
 *  modules/kprobe/arch/dbi_kprobes.h
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
 * 2006-2007    Ekaterina Gorelkina <e.gorelkina@samsung.com>: initial implementation for ARM and MIPS
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 *
 */


#define REENTER

struct kprobe;
struct pt_regs;
struct kretprobe;
struct kretprobe_instance;
struct task_struct;
struct kprobe_ctlblk;

struct prev_kprobe {
	struct kprobe *kp;
	unsigned long status;
};

void kretprobe_trampoline (void);

extern void __arch_prepare_kretprobe (struct kretprobe *rp, struct pt_regs *regs);
extern int arch_prepare_kprobe (struct kprobe *p);
extern int arch_prepare_kretprobe (struct kretprobe *p);
extern int arch_prepare_uretprobe (struct kretprobe *p, struct task_struct *task);
extern void arch_arm_kprobe (struct kprobe *p);
extern void arch_arm_kretprobe (struct kretprobe *p);
extern void arch_arm_uprobe (struct kprobe *p, struct task_struct *tsk);
extern void arch_arm_uretprobe (struct kretprobe *p, struct task_struct *tsk);
extern void arch_disarm_kprobe (struct kprobe *p);
extern void arch_disarm_kretprobe (struct kretprobe *p);
extern void arch_disarm_uprobe (struct kprobe *p, struct task_struct *tsk);
extern void arch_disarm_uretprobe (struct kretprobe *p, struct task_struct *tsk);
extern int arch_init_kprobes (void);
extern void dbi_arch_exit_kprobes (void);
extern int patch_suspended_task(struct kretprobe *rp, struct task_struct *tsk);

void dbi_arch_uprobe_return (void);

void arch_remove_kprobe (struct kprobe *p, struct task_struct *task);

void prepare_singlestep (struct kprobe *p, struct pt_regs *regs);
void save_previous_kprobe (struct kprobe_ctlblk *kcb, struct kprobe *cur_p);
void restore_previous_kprobe (struct kprobe_ctlblk *kcb);
void set_current_kprobe (struct kprobe *p, struct pt_regs *regs, struct kprobe_ctlblk *kcb);

int setjmp_pre_handler (struct kprobe *p, struct pt_regs *regs);

void dbi_jprobe_return (void);

int longjmp_break_handler (struct kprobe *p, struct pt_regs *regs);

void kretprobe_trampoline_holder (void);

int trampoline_probe_handler (struct kprobe *p, struct pt_regs *regs);

int arch_init_module_dependencies(void);
int asm_init_module_dependencies(void);

#endif				/* _DBI_ARCH_KPROBES_H */
