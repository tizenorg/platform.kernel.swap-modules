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
#include <ksyms.h>

extern struct hlist_head kprobe_insn_pages;
extern struct hlist_head uprobe_insn_pages;

void arch_remove_kprobe(struct kprobe *p)
{
	// TODO: check boostable for x86 and MIPS
	free_insn_slot(&kprobe_insn_pages, NULL, p->ainsn.insn);
}

void arch_remove_uprobe(struct kprobe *p, struct task_struct *task)
{
	if (p->tgid == 0) {
		panic("arch_remove_uprobe for tgid == 0!!!");
	}

#ifdef CONFIG_ARM
	free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_arm);
	free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_thumb);
#else /* CONFIG_ARM */
	free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn);
#endif /* CONFIG_ARM */
}

void arch_arm_uretprobe (struct kretprobe *p, struct task_struct *tsk)
{
}
EXPORT_SYMBOL_GPL(arch_arm_uretprobe);

void arch_disarm_uprobe (struct kprobe *p, struct task_struct *tsk)
{
	if (!write_proc_vm_atomic (tsk, (unsigned long) p->addr, &p->opcode, sizeof (p->opcode))) {
		panic ("failed to write memory: tgid=%u, addr=%p!\n", tsk->tgid, p->addr);
	}
}
EXPORT_SYMBOL_GPL(arch_disarm_uprobe);

int arch_init_module_dependencies(void)
{
	int ret;

	sched_addr = swap_ksyms("__switch_to");
	fork_addr = swap_ksyms("do_fork");
	exit_addr = swap_ksyms("do_exit");

	if ((void *)sched_addr == NULL ||
				(void *)fork_addr == NULL ||
				(void *)exit_addr == NULL) {
		return -ESRCH;
	}

	ret = init_module_dependencies();
	if (ret) {
		return ret;
	}

	return asm_init_module_dependencies();
}
