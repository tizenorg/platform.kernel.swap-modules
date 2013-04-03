/*
 *  Kernel Probes (KProbes)
 *  kernel/kprobes.c
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
 *  modules/kprobe/dbi_kprobes.h
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
#include "arch/dbi_kprobes.h"
#include "arch/asm/dbi_kprobes.h"

#include "dbi_kdebug.h"
#include "dbi_kprobes_deps.h"
#include "dbi_insn_slots.h"
#include <ksyms.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif

#include <linux/hash.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

extern struct hlist_head kprobe_insn_pages;

DEFINE_PER_CPU(struct kprobe *, current_kprobe) = NULL;
static DEFINE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);

DEFINE_SPINLOCK(kretprobe_lock);	/* Protects kretprobe_inst_table */
EXPORT_SYMBOL_GPL(kretprobe_lock);
static DEFINE_PER_CPU(struct kprobe *, kprobe_instance) = NULL;

struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];
static struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];

atomic_t kprobe_count;
EXPORT_SYMBOL_GPL(kprobe_count);

void kretprobe_assert(struct kretprobe_instance *ri, unsigned long orig_ret_address, unsigned long trampoline_address)
{
	if (!orig_ret_address || (orig_ret_address == trampoline_address)) {
		struct task_struct *task;
		if (ri == NULL) {
			panic("kretprobe BUG!: ri = NULL\n");
		}

		task = ri->task;

		if (task == NULL) {
			panic("kretprobe BUG!: task = NULL\n");
		}

		if (ri->rp == NULL) {
			panic("kretprobe BUG!: ri->rp = NULL\n");
		}

		panic("kretprobe BUG!: Processing kretprobe %p @ %p (%d/%d - %s)\n",
		      ri->rp, ri->rp->kp.addr, ri->task->tgid, ri->task->pid, ri->task->comm);
	}
}

/* We have preemption disabled.. so it is safe to use __ versions */
static inline void set_kprobe_instance(struct kprobe *kp)
{
	__get_cpu_var(kprobe_instance) = kp;
}

static inline void reset_kprobe_instance(void)
{
	__get_cpu_var(kprobe_instance) = NULL;
}

/* kprobe_running() will just return the current_kprobe on this CPU */
struct kprobe *kprobe_running(void)
{
	return __get_cpu_var(current_kprobe);
}

void reset_current_kprobe(void)
{
	__get_cpu_var(current_kprobe) = NULL;
}

struct kprobe_ctlblk *get_kprobe_ctlblk(void)
{
	return &__get_cpu_var(kprobe_ctlblk);
}

/*
 * This routine is called either:
 * 	- under the kprobe_mutex - during kprobe_[un]register()
 * 				OR
 * 	- with preemption disabled - from arch/xxx/kernel/kprobes.c
 */
struct kprobe *get_kprobe(void *addr)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;

	head = &kprobe_table[hash_ptr (addr, KPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(p, node, head, hlist) {
		if (p->addr == addr) {
			return p;
		}
	}

	return NULL;
}

/*
 * Aggregate handlers for multiple kprobes support - these handlers
 * take care of invoking the individual kprobe handlers on p->list
 */
static int aggr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *kp;
	int ret;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->pre_handler) {
			set_kprobe_instance(kp);
			ret = kp->pre_handler(kp, regs);
			if (ret)
				return ret;
		}
		reset_kprobe_instance();
	}

	return 0;
}

static void aggr_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	struct kprobe *kp;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->post_handler) {
			set_kprobe_instance(kp);
			kp->post_handler(kp, regs, flags);
			reset_kprobe_instance();
		}
	}
}

static int aggr_fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur = __get_cpu_var(kprobe_instance);

	/*
	 * if we faulted "during" the execution of a user specified
	 * probe handler, invoke just that probe's fault handler
	 */
	if (cur && cur->fault_handler) {
		if (cur->fault_handler(cur, regs, trapnr))
			return 1;
	}

	return 0;
}

static int aggr_break_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *cur = __get_cpu_var(kprobe_instance);
	int ret = 0;
	DBPRINTF ("cur = 0x%p\n", cur);
	if (cur)
		DBPRINTF ("cur = 0x%p cur->break_handler = 0x%p\n", cur, cur->break_handler);

	if (cur && cur->break_handler) {
		if (cur->break_handler(cur, regs))
			ret = 1;
	}
	reset_kprobe_instance();

	return ret;
}

/* Walks the list and increments nmissed count for multiprobe case */
void kprobes_inc_nmissed_count(struct kprobe *p)
{
	struct kprobe *kp;
	if (p->pre_handler != aggr_pre_handler) {
		p->nmissed++;
	} else {
		list_for_each_entry_rcu(kp, &p->list, list) {
			++kp->nmissed;
		}
	}
}

/* Called with kretprobe_lock held */
struct kretprobe_instance *get_free_rp_inst(struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;

	hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
		return ri;
	}

	if (!alloc_nodes_kretprobe(rp)) {
		hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
			return ri;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(get_free_rp_inst);

/* Called with kretprobe_lock held */
struct kretprobe_instance *get_free_rp_inst_no_alloc(struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;

	hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
		return ri;
	}

	return NULL;
}

/* Called with kretprobe_lock held */
struct kretprobe_instance *get_used_rp_inst(struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;

	hlist_for_each_entry(ri, node, &rp->used_instances, uflist) {
		return ri;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(get_used_rp_inst);

/* Called with kretprobe_lock held */
void add_rp_inst (struct kretprobe_instance *ri)
{
	/*
	 * Remove rp inst off the free list -
	 * Add it back when probed function returns
	 */
	hlist_del(&ri->uflist);

	/* Add rp inst onto table */
	INIT_HLIST_NODE(&ri->hlist);

	hlist_add_head(&ri->hlist, &kretprobe_inst_table[hash_ptr(ri->task, KPROBE_HASH_BITS)]);

	/* Also add this rp inst to the used list. */
	INIT_HLIST_NODE(&ri->uflist);
	hlist_add_head(&ri->uflist, &ri->rp->used_instances);
}
EXPORT_SYMBOL_GPL(add_rp_inst);

/* Called with kretprobe_lock held */
void recycle_rp_inst(struct kretprobe_instance *ri)
{
	if (ri->rp) {
		hlist_del(&ri->hlist);
		/* remove rp inst off the used list */
		hlist_del(&ri->uflist);
		/* put rp inst back onto the free list */
		INIT_HLIST_NODE(&ri->uflist);
		hlist_add_head(&ri->uflist, &ri->rp->free_instances);
	} else if (!ri->rp2) {
		/*
		 * This is __switch_to retprobe instance.  It has neither rp nor rp2.
		 */
		hlist_del(&ri->hlist);
	}
}
EXPORT_SYMBOL_GPL(recycle_rp_inst);

struct hlist_head *kretprobe_inst_table_head(void *hash_key)
{
	return &kretprobe_inst_table[hash_ptr(hash_key, KPROBE_HASH_BITS)];
}
EXPORT_SYMBOL_GPL(kretprobe_inst_table_head);

void free_rp_inst(struct kretprobe *rp)
{
	struct kretprobe_instance *ri;
	while ((ri = get_free_rp_inst_no_alloc(rp)) != NULL) {
		hlist_del(&ri->uflist);
		kfree(ri);
	}
}
EXPORT_SYMBOL_GPL(free_rp_inst);

/*
 * Keep all fields in the kprobe consistent
 */
static inline void copy_kprobe(struct kprobe *old_p, struct kprobe *p)
{
	memcpy(&p->opcode, &old_p->opcode, sizeof(kprobe_opcode_t));
	memcpy(&p->ainsn, &old_p->ainsn, sizeof(struct arch_specific_insn));
	p->ss_addr = old_p->ss_addr;
#ifdef CONFIG_ARM
	p->safe_arm = old_p->safe_arm;
	p->safe_thumb = old_p->safe_thumb;
#endif
}

/*
 * Add the new probe to old_p->list. Fail if this is the
 * second jprobe at the address - two jprobes can't coexist
 */
static int add_new_kprobe(struct kprobe *old_p, struct kprobe *p)
{
	if (p->break_handler) {
		if (old_p->break_handler) {
			return -EEXIST;
		}

		list_add_tail_rcu(&p->list, &old_p->list);
		old_p->break_handler = aggr_break_handler;
	} else {
		list_add_rcu(&p->list, &old_p->list);
	}

	if (p->post_handler && !old_p->post_handler) {
		old_p->post_handler = aggr_post_handler;
	}

	return 0;
}

/**
 * hlist_replace_rcu - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * The @old entry will be replaced with the @new entry atomically.
 */
inline void dbi_hlist_replace_rcu(struct hlist_node *old, struct hlist_node *new)
{
	struct hlist_node *next = old->next;

	new->next = next;
	new->pprev = old->pprev;
	smp_wmb();
	if (next)
		new->next->pprev = &new->next;
	if (new->pprev)
		*new->pprev = new;
	old->pprev = LIST_POISON2;
}

/*
 * Fill in the required fields of the "manager kprobe". Replace the
 * earlier kprobe in the hlist with the manager kprobe
 */
static inline void add_aggr_kprobe(struct kprobe *ap, struct kprobe *p)
{
	copy_kprobe(p, ap);
	ap->addr = p->addr;
	ap->pre_handler = aggr_pre_handler;
	ap->fault_handler = aggr_fault_handler;
	if (p->post_handler)
		ap->post_handler = aggr_post_handler;
	if (p->break_handler)
		ap->break_handler = aggr_break_handler;

	INIT_LIST_HEAD(&ap->list);
	list_add_rcu(&p->list, &ap->list);

	dbi_hlist_replace_rcu(&p->hlist, &ap->hlist);
}

/*
 * This is the second or subsequent kprobe at the address - handle
 * the intricacies
 */
int register_aggr_kprobe(struct kprobe *old_p, struct kprobe *p)
{
	int ret = 0;
	struct kprobe *ap;
	DBPRINTF ("start\n");

	DBPRINTF ("p = %p old_p = %p \n", p, old_p);
	if (old_p->pre_handler == aggr_pre_handler) {
		DBPRINTF ("aggr_pre_handler \n");

		copy_kprobe(old_p, p);
		ret = add_new_kprobe(old_p, p);
	} else {
		DBPRINTF ("kzalloc\n");
#ifdef kzalloc
		ap = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
#else
		ap = kmalloc(sizeof(struct kprobe), GFP_KERNEL);
		if (ap)
			memset(ap, 0, sizeof(struct kprobe));
#endif
		if (!ap)
			return -ENOMEM;
		add_aggr_kprobe(ap, old_p);
		copy_kprobe(ap, p);
		DBPRINTF ("ap = %p p = %p old_p = %p \n", ap, p, old_p);
		ret = add_new_kprobe(ap, p);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(register_aggr_kprobe);

int dbi_register_kprobe(struct kprobe *p)
{
	struct kprobe *old_p;
	int ret = 0;
	/*
	 * If we have a symbol_name argument look it up,
	 * and add it to the address.  That way the addr
	 * field can either be global or relative to a symbol.
	 */
	if (p->symbol_name) {
		if (p->addr)
			return -EINVAL;
		p->addr = (kprobe_opcode_t *)swap_ksyms(p->symbol_name);
	}

	if (!p->addr)
		return -EINVAL;
	DBPRINTF ("p->addr = 0x%p\n", p->addr);
	p->addr = (kprobe_opcode_t *)(((char *)p->addr) + p->offset);
	DBPRINTF ("p->addr = 0x%p p = 0x%p\n", p->addr, p);

#ifdef KPROBES_PROFILE
	p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
	p->hnd_tm_sum.tv_sec = p->hnd_tm_sum.tv_usec = 0;
	p->count = 0;
#endif
	p->mod_refcounted = 0;
	p->nmissed = 0;

	old_p = get_kprobe(p->addr);
	if (old_p) {
		ret = register_aggr_kprobe(old_p, p);
		if (!ret)
			atomic_inc(&kprobe_count);
		goto out;
	}

	if ((ret = arch_prepare_kprobe(p)) != 0)
		goto out;

	DBPRINTF ("before out ret = 0x%x\n", ret);
	INIT_HLIST_NODE(&p->hlist);
	hlist_add_head_rcu(&p->hlist, &kprobe_table[hash_ptr(p->addr, KPROBE_HASH_BITS)]);
	arch_arm_kprobe(p);

out:
	DBPRINTF ("out ret = 0x%x\n", ret);
	return ret;
}

void dbi_unregister_kprobe(struct kprobe *p, struct task_struct *task)
{
	struct kprobe *old_p, *list_p;
	int cleanup_p;

	old_p = get_kprobe(p->addr);
	DBPRINTF ("dbi_unregister_kprobe p=%p old_p=%p", p, old_p);
	if (unlikely (!old_p))
		return;

	if (p != old_p) {
		list_for_each_entry_rcu(list_p, &old_p->list, list)
			if (list_p == p)
				/* kprobe p is a valid probe */
				goto valid_p;
		return;
	}

valid_p:
	DBPRINTF ("dbi_unregister_kprobe valid_p");
	if ((old_p == p) || ((old_p->pre_handler == aggr_pre_handler) &&
	    (p->list.next == &old_p->list) && (p->list.prev == &old_p->list))) {
		/* Only probe on the hash list */
		arch_disarm_kprobe(p);
		hlist_del_rcu(&old_p->hlist);
		cleanup_p = 1;
	} else {
		list_del_rcu(&p->list);
		cleanup_p = 0;
	}
	DBPRINTF ("dbi_unregister_kprobe cleanup_p=%d", cleanup_p);

	if (cleanup_p) {
		if (p != old_p) {
			list_del_rcu(&p->list);
			kfree(old_p);
		}

		if (!in_atomic()) {
			synchronize_sched();
		}

		arch_remove_kprobe(p);
	} else {
		if (p->break_handler)
			old_p->break_handler = NULL;
		if (p->post_handler) {
			list_for_each_entry_rcu(list_p, &old_p->list, list) {
				if (list_p->post_handler) {
					cleanup_p = 2;
					break;
				}
			}

			if (cleanup_p == 0)
				old_p->post_handler = NULL;
		}
	}
}

int dbi_register_jprobe(struct jprobe *jp)
{
	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_pre_handler;
	jp->kp.break_handler = longjmp_break_handler;

	return dbi_register_kprobe(&jp->kp);
}

void dbi_unregister_jprobe(struct jprobe *jp)
{
	dbi_unregister_kprobe(&jp->kp, NULL);
}

/*
 * This kprobe pre_handler is registered with every kretprobe. When probe
 * hits it will set up the return probe.
 */
int pre_handler_kretprobe(struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe *rp = container_of(p, struct kretprobe, kp);
	unsigned long flags = 0;
	DBPRINTF ("START\n");

	/*TODO: consider to only swap the RA after the last pre_handler fired */
	spin_lock_irqsave(&kretprobe_lock, flags);
	if (!rp->disarm)
		__arch_prepare_kretprobe(rp, regs);
	spin_unlock_irqrestore(&kretprobe_lock, flags);
	DBPRINTF ("END\n");
	return 0;
}
EXPORT_SYMBOL_GPL(pre_handler_kretprobe);

struct kretprobe *sched_rp;

#define SCHED_RP_NR 200
#define COMMON_RP_NR 10

int alloc_nodes_kretprobe(struct kretprobe *rp)
{
	int alloc_nodes;
	struct kretprobe_instance *inst;
	int i;

	DBPRINTF("Alloc aditional mem for retprobes");

	if ((unsigned long)rp->kp.addr == sched_addr) {
		rp->maxactive += SCHED_RP_NR;//max (100, 2 * NR_CPUS);
		alloc_nodes = SCHED_RP_NR;
	} else {
#if 1//def CONFIG_PREEMPT
		rp->maxactive += max (COMMON_RP_NR, 2 * NR_CPUS);
#else
		rp->maxacpptive += NR_CPUS;
#endif
		alloc_nodes = COMMON_RP_NR;
	}

	for (i = 0; i < alloc_nodes; i++) {
		inst = kmalloc(sizeof(struct kretprobe_instance), GFP_ATOMIC);
		if (inst == NULL) {
			free_rp_inst(rp);
			return -ENOMEM;
		}
		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	return 0;
}

int dbi_register_kretprobe(struct kretprobe *rp)
{
	int ret = 0;
	struct kretprobe_instance *inst;
	int i;
	DBPRINTF ("START");

	rp->kp.pre_handler = pre_handler_kretprobe;
	rp->kp.post_handler = NULL;
	rp->kp.fault_handler = NULL;
	rp->kp.break_handler = NULL;

	rp->disarm = 0;

	/* Pre-allocate memory for max kretprobe instances */
	if ((unsigned long)rp->kp.addr == sched_addr) {
		rp->maxactive = SCHED_RP_NR;//max (100, 2 * NR_CPUS);
		rp->kp.pre_handler = NULL; //not needed for __switch_to
	} else if ((unsigned long)rp->kp.addr == exit_addr) {
		rp->kp.pre_handler = NULL; //not needed for do_exit
		rp->maxactive = 0;
	} else if (rp->maxactive <= 0) {
#if 1//def CONFIG_PREEMPT
		rp->maxactive = max (COMMON_RP_NR, 2 * NR_CPUS);
#else
		rp->maxactive = NR_CPUS;
#endif
	}
	INIT_HLIST_HEAD(&rp->used_instances);
	INIT_HLIST_HEAD(&rp->free_instances);
	for (i = 0; i < rp->maxactive; i++) {
		inst = kmalloc(sizeof(struct kretprobe_instance), GFP_KERNEL);
		if (inst == NULL) {
			free_rp_inst(rp);
			return -ENOMEM;
		}
		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	rp->nmissed = 0;
	/* Establish function entry probe point */
	if ((ret = dbi_register_kprobe(&rp->kp)) != 0)
		free_rp_inst(rp);

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	if ((unsigned long)rp->kp.addr == sched_addr) {
		sched_rp = rp;
	}

	return ret;
}

static int dbi_disarm_krp_inst(struct kretprobe_instance *ri);

void dbi_unregister_kretprobe(struct kretprobe *rp)
{
	unsigned long flags;
	struct kretprobe_instance *ri;

	dbi_unregister_kprobe(&rp->kp, NULL);

	/* No race here */
	spin_lock_irqsave(&kretprobe_lock, flags);

	if ((unsigned long)rp->kp.addr == sched_addr)
		sched_rp = NULL;

	while ((ri = get_used_rp_inst(rp)) != NULL) {
		if (dbi_disarm_krp_inst(ri) == 0)
			recycle_rp_inst(ri);
		else
			panic("%s (%d/%d): cannot disarm krp instance (%08lx)",
					ri->task->comm, ri->task->tgid, ri->task->pid,
					(unsigned long)rp->kp.addr);
	}

	spin_unlock_irqrestore(&kretprobe_lock, flags);
	free_rp_inst(rp);
}

struct kretprobe *clone_kretprobe(struct kretprobe *rp)
{
	struct kprobe *old_p;
	struct kretprobe *clone = NULL;
	int ret;

	clone = kmalloc(sizeof(struct kretprobe), GFP_KERNEL);
	if (!clone) {
		DBPRINTF ("failed to alloc memory for clone probe %p!", rp->kp.addr);
		return NULL;
	}
	memcpy(clone, rp, sizeof(struct kretprobe));
	clone->kp.pre_handler = pre_handler_kretprobe;
	clone->kp.post_handler = NULL;
	clone->kp.fault_handler = NULL;
	clone->kp.break_handler = NULL;
	old_p = get_kprobe(rp->kp.addr);
	if (old_p) {
		ret = register_aggr_kprobe(old_p, &clone->kp);
		if (ret) {
			kfree(clone);
			return NULL;
		}
		atomic_inc(&kprobe_count);
	}

	return clone;
}
EXPORT_SYMBOL_GPL(clone_kretprobe);

static void inline set_task_trampoline(struct task_struct *p, struct kretprobe_instance *ri, unsigned long tramp_addr)
{
	unsigned long pc = arch_get_task_pc(p);
	if (pc == tramp_addr)
		panic("[%d] %s (%d/%d): pc = %08lx --- [%d] %s (%d/%d)\n",
				task_cpu(p), p->comm, p->tgid, p->pid, pc,
				task_cpu(current), current->comm, current->tgid, current->pid);
	ri->ret_addr = (kprobe_opcode_t *)pc;
	arch_set_task_pc(p, tramp_addr);
}

static void inline rm_task_trampoline(struct task_struct *p, struct kretprobe_instance *ri)
{
	arch_set_task_pc(p, (unsigned long)ri->ret_addr);
}

static int dbi_disarm_krp_inst(struct kretprobe_instance *ri)
{
	kprobe_opcode_t *tramp = (kprobe_opcode_t *)&kretprobe_trampoline;
	kprobe_opcode_t *sp = ri->sp;
	kprobe_opcode_t *found = NULL;
	int retval = -ENOENT;

	if (!sp) {
		unsigned long pc = arch_get_task_pc(ri->task);

		printk("---> [%d] %s (%d/%d): pc = %08lx, ra = %08lx, tramp= %08lx (%08lx)\n",
				task_cpu(ri->task),
				ri->task->comm, ri->task->tgid, ri->task->pid,
				pc, (unsigned long)ri->ret_addr,
				(unsigned long)tramp,
				(unsigned long)(ri->rp ? ri->rp->kp.addr: NULL));

		/* __switch_to retprobe handling */
		if (pc == (unsigned long)tramp) {
			rm_task_trampoline(ri->task, ri);
			return 0;
		}

		return -EINVAL;
	}

	while (sp > ri->sp - RETPROBE_STACK_DEPTH) {
		if ((unsigned long)*sp == (unsigned long)tramp) {
			found = sp;
			break;
		}
		sp--;
	}

	if (found) {
		printk("---> [%d] %s (%d/%d): tramp (%08lx) found at %08lx (%08lx /%+d) - %p\n",
				task_cpu(ri->task),
				ri->task->comm, ri->task->tgid, ri->task->pid,
				(unsigned long)tramp,
				(unsigned long)found, (unsigned long)ri->sp, found - ri->sp,
				ri->rp ? ri->rp->kp.addr: NULL);
		*found = (unsigned long)ri->ret_addr;
		retval = 0;
	} else {
		printk("---> [%d] %s (%d/%d): tramp (%08lx) NOT found at sp = %08lx - %p\n",
				task_cpu(ri->task),
				ri->task->comm, ri->task->tgid, ri->task->pid,
				(unsigned long)tramp,
				(unsigned long)ri->sp, ri->rp ? ri->rp->kp.addr: NULL);
	}

	return retval;
}

int patch_suspended_task(struct kretprobe *rp, struct task_struct *task)
{
	struct kretprobe_instance *ri;
	unsigned long flags;
	kprobe_opcode_t *tramp = (kprobe_opcode_t *)&kretprobe_trampoline;

	spin_lock_irqsave(&kretprobe_lock, flags);

	ri = get_free_rp_inst(rp);
	if (!ri)
		return -ENOMEM;

	ri->rp = rp;
	ri->rp2 = NULL;
	ri->task = task;
	ri->sp = NULL;
	set_task_trampoline(task, ri, (unsigned long)tramp);
	add_rp_inst(ri);

	spin_unlock_irqrestore(&kretprobe_lock, flags);
	return 0;
}

static int __init init_kprobes(void)
{
	int i, err = 0;

	/* FIXME allocate the probe table, currently defined statically */
	/* initialize all list heads */
	for (i = 0; i < KPROBE_TABLE_SIZE; ++i) {
		INIT_HLIST_HEAD(&kprobe_table[i]);
		INIT_HLIST_HEAD(&kretprobe_inst_table[i]);
	}
	atomic_set(&kprobe_count, 0);

	err = arch_init_kprobes();

	DBPRINTF ("init_kprobes: arch_init_kprobes - %d", err);

	return err;
}

static void __exit exit_kprobes(void)
{
	dbi_arch_exit_kprobes();
}

module_init(init_kprobes);
module_exit(exit_kprobes);

EXPORT_SYMBOL_GPL(dbi_register_kprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_kprobe);
EXPORT_SYMBOL_GPL(dbi_register_jprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_jprobe);
EXPORT_SYMBOL_GPL(dbi_jprobe_return);
EXPORT_SYMBOL_GPL(dbi_register_kretprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_kretprobe);

MODULE_LICENSE("Dual BSD/GPL");
