#ifndef _DBI_UPROBES_H
#define _DBI_UPROBES_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/dbi_uprobes.h
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

#include "dbi_kprobes.h"

struct uprobe {
	struct kprobe kp;
	struct task_struct *task;
	struct slot_manager *sm;
};

typedef unsigned long (*uprobe_pre_entry_handler_t)(void *priv_arg, struct pt_regs * regs);

struct ujprobe {
	struct uprobe up;
	/* probe handling code to jump to */
	void *entry;
	// handler whichw willb bec called before 'entry'
	uprobe_pre_entry_handler_t pre_entry;
	void *priv_arg;
};

struct uretprobe_instance;

typedef int (*uretprobe_handler_t)(struct uretprobe_instance *, struct pt_regs *, void *);

/*
 * Function-return probe -
 * Note:
 * User needs to provide a handler function, and initialize maxactive.
 * maxactive - The maximum number of instances of the probed function that
 * can be active concurrently.
 * nmissed - tracks the number of times the probed function's return was
 * ignored, due to maxactive being too low.
 *
 */
struct uretprobe {
	struct uprobe up;
	uretprobe_handler_t handler;
	void *priv_arg;
	int maxactive;
	int nmissed;
	struct hlist_head free_instances;
	struct hlist_head used_instances;
};

struct uretprobe_instance {
	/* either on free list or used list */
	struct hlist_node uflist;
	struct hlist_node hlist;
	struct uretprobe *rp;
	kprobe_opcode_t *ret_addr;
	kprobe_opcode_t *sp;
	struct task_struct *task;
};

int dbi_register_uprobe(struct uprobe *p, int atomic);
void dbi_unregister_uprobe(struct uprobe *p, int atomic);

int dbi_register_ujprobe(struct ujprobe *jp, int atomic);
void dbi_unregister_ujprobe(struct ujprobe *jp, int atomic);

int dbi_register_uretprobe(struct uretprobe *rp, int atomic);
void dbi_unregister_uretprobe(struct uretprobe *rp, int atomic);

void dbi_unregister_all_uprobes(struct task_struct *task, int atomic);

void dbi_uprobe_return(void);
struct kprobe *get_ukprobe(void *addr, pid_t tgid);
struct kprobe *get_ukprobe_by_insn_slot(void *addr, pid_t tgid, struct pt_regs *regs);

static inline struct uprobe *kp2up(struct kprobe *p)
{
	return container_of(p, struct uprobe, kp);
}

static inline struct kprobe *up2kp(struct uprobe *p)
{
	return &p->kp;
}

void disarm_uprobe(struct uprobe *p);

int trampoline_uprobe_handler(struct kprobe *p, struct pt_regs *regs);

#endif /*  _DBI_UPROBES_H */
