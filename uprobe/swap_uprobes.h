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

int dbi_register_uprobe(struct kprobe *p, struct task_struct *task, int atomic);
void dbi_unregister_uprobe(struct kprobe *p, struct task_struct *task, int atomic);

int dbi_register_ujprobe(struct task_struct *task, struct jprobe *jp, int atomic);
void dbi_unregister_ujprobe(struct task_struct *task, struct jprobe *jp, int atomic);

int dbi_register_uretprobe(struct task_struct *task, struct kretprobe *rp, int atomic);
void dbi_unregister_uretprobe(struct task_struct *task, struct kretprobe *rp, int atomic, int not_rp2);

void dbi_unregister_all_uprobes(struct task_struct *task, int atomic);

void dbi_uprobe_return(void);
struct kprobe *get_uprobe(kprobe_opcode_t *addr, pid_t tgid);

void disarm_uprobe(struct kprobe *p, struct task_struct *task);

extern spinlock_t uretprobe_lock;
struct hlist_head *uretprobe_inst_table_head(void *hash_key);
void recycle_urp_inst(struct kretprobe_instance *ri);

#endif /*  _DBI_UPROBES_H */
