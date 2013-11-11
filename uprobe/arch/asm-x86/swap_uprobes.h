/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/uprobe/arch/asm-x86/swap_uprobes.h
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

#ifndef _ARM_SWAP_UPROBES_H
#define _ARM_SWAP_UPROBES_H

#include <asm/dbi_kprobes.h>

static inline void arch_ujprobe_return(void)
{
}

int arch_prepare_uprobe(struct uprobe *up, struct hlist_head *page_list);
int setjmp_upre_handler(struct kprobe *p, struct pt_regs *regs);
static inline int longjmp_break_uhandler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static inline int arch_opcode_analysis_uretprobe(struct uretprobe *rp)
{
	return 0;
}

void arch_prepare_uretprobe(struct uretprobe_instance *ri, struct pt_regs *regs);
unsigned long arch_get_trampoline_addr(struct kprobe *p, struct pt_regs *regs);
void arch_set_orig_ret_addr(unsigned long orig_ret_addr, struct pt_regs *regs);

static inline unsigned long swap_get_uarg(struct pt_regs *regs, unsigned long n)
{
	u32 *ptr, addr = 0;

	/* 1 - return address saved on top of the stack */
	ptr = (u32 *)regs->sp + n + 1;
	if (get_user(addr, ptr))
		printk("failed to dereference a pointer, ptr=%p\n", ptr);

	return addr;
}

int swap_arch_init_uprobes(void);
void swap_arch_exit_uprobes(void);

#endif /* _ARM_SWAP_UPROBES_H */
