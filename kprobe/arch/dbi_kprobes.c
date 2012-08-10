/*
 *  Kernel Probes (KProbes)
 *  arch/<arch>/kernel/kprobes.c
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
 *  modules/kprobe/arch/dbi_kprobes.c
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

#include "dbi_kprobes.h"
#include "../dbi_kprobes.h"
#include "asm/dbi_kprobes.h"

#include "../dbi_kdebug.h"
#include "../dbi_insn_slots.h"
#include "../dbi_kprobes_deps.h"

#include <linux/module.h>

extern unsigned int *sched_addr;
extern unsigned int *fork_addr;

extern struct hlist_head kprobe_insn_pages;
extern struct hlist_head uprobe_insn_pages;

static int ksyms = INVALID_VALUE;
module_param(ksyms, uint, 0);
MODULE_PARM_DESC(ksyms, "kallsyms_lookup_name address");

extern unsigned long (*kallsyms_search) (const char *name);

void arch_remove_kprobe (struct kprobe *p, struct task_struct *task)
{
	if (p->tgid) {
#ifdef CONFIG_ARM
		free_insn_slot (&uprobe_insn_pages, task, \
				p->ainsn.insn_arm, (p->ainsn.boostable == 1));
		free_insn_slot (&uprobe_insn_pages, task, \
				p->ainsn.insn_thumb, (p->ainsn.boostable == 1));
#else /* CONFIG_ARM */
		free_insn_slot (&uprobe_insn_pages, task, \
				p->ainsn.insn, (p->ainsn.boostable == 1));
#endif /* CONFIG_ARM */
	} else {
		free_insn_slot (&kprobe_insn_pages, NULL, \
				p->ainsn.insn, (p->ainsn.boostable == 1));
	}
}

void arch_arm_uprobe (struct kprobe *p, struct task_struct *tsk)
{
	kprobe_opcode_t insn = BREAKPOINT_INSTRUCTION;

	if (!write_proc_vm_atomic (tsk, (unsigned long) p->addr, &insn, sizeof (insn)))
		panic ("failed to write memory %p!\n", p->addr);
}

void arch_arm_uretprobe (struct kretprobe *p, struct task_struct *tsk)
{
}

void arch_disarm_uprobe (struct kprobe *p, struct task_struct *tsk)
{
	if (!write_proc_vm_atomic (tsk, (unsigned long) p->addr, &p->opcode, sizeof (p->opcode)))
		panic ("failed to write memory %p!\n", p->addr);
}
EXPORT_SYMBOL_GPL(arch_disarm_uprobe);

void arch_disarm_uretprobe (struct kretprobe *p, struct task_struct *tsk)
{
}

int arch_init_module_dependencies()
{

	kallsyms_search = (void *) ksyms;
	DBPRINTF ("kallsyms=0x%08x\n", ksyms);

	sched_addr = (unsigned int *)kallsyms_search("__switch_to");//"schedule");
	fork_addr = (unsigned int *)kallsyms_search("do_fork");

	init_module_dependencies();

	return asm_init_module_dependencies();
}
