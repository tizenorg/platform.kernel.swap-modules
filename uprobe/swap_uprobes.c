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


#include "swap_uprobes.h"
#include "dbi_kdebug.h"

#include <asm/swap_uprobes.h>

#include <linux/hash.h>
#include <linux/mempolicy.h>
#include <linux/module.h>
#include <dbi_insn_slots.h>

enum {
	UPROBE_HASH_BITS  = 10,
	UPROBE_TABLE_SIZE = (1 << UPROBE_HASH_BITS)
};

struct hlist_head uprobe_insn_slot_table[UPROBE_TABLE_SIZE];
struct hlist_head uprobe_table[UPROBE_TABLE_SIZE];
struct hlist_head uprobe_insn_pages;

DEFINE_SPINLOCK(uretprobe_lock);	/* Protects uretprobe_inst_table */
static struct hlist_head uretprobe_inst_table[UPROBE_TABLE_SIZE];

#define DEBUG_PRINT_HASH_TABLE 0

#if DEBUG_PRINT_HASH_TABLE
void print_kprobe_hash_table(void)
{
	int i;
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;

	// print uprobe table
	for (i = 0; i < KPROBE_TABLE_SIZE; ++i) {
		head = &kprobe_table[i];
		hlist_for_each_entry_rcu (p, node, head, is_hlist_arm) {
			printk("####### find K tgid=%u, addr=%x\n",
					p->tgid, p->addr);
		}
	}
}

void print_kretprobe_hash_table(void)
{
	int i;
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;

	// print uprobe table
	for (i = 0; i < KPROBE_TABLE_SIZE; ++i) {
		head = &kretprobe_inst_table[i];
		hlist_for_each_entry_rcu (p, node, head, is_hlist_arm) {
			printk("####### find KR tgid=%u, addr=%x\n",
					p->tgid, p->addr);
		}
	}
}

void print_uprobe_hash_table(void)
{
	int i;
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;

	// print uprobe table
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		head = &uprobe_insn_slot_table[i];
		hlist_for_each_entry_rcu (p, node, head, is_hlist_arm) {
			printk("####### find U tgid=%u, addr=%x\n",
					p->tgid, p->addr);
		}
	}
}
#endif

/*
 * Keep all fields in the uprobe consistent
 */
static inline void copy_uprobe(struct kprobe *old_p, struct kprobe *p)
{
	memcpy(&p->opcode, &old_p->opcode, sizeof(kprobe_opcode_t));
	memcpy(&p->ainsn, &old_p->ainsn, sizeof(struct arch_specific_insn));
	p->tgid = old_p->tgid;
	p->ss_addr = old_p->ss_addr;
#ifdef CONFIG_ARM
	p->safe_arm = old_p->safe_arm;
	p->safe_thumb = old_p->safe_thumb;
#endif
}

/*
 * Aggregate handlers for multiple uprobes support - these handlers
 * take care of invoking the individual uprobe handlers on p->list
 */
static int aggr_pre_uhandler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *kp;
	int ret;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->pre_handler) {
			ret = kp->pre_handler(kp, regs);
			if (ret) {
				return ret;
			}
		}
	}

	return 0;
}

static void aggr_post_uhandler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	struct kprobe *kp;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->post_handler) {
			kp->post_handler(kp, regs, flags);
		}
	}
}

static int aggr_fault_uhandler(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	return 0;
}

static int aggr_break_uhandler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

/*
 * Add the new probe to old_p->list. Fail if this is the
 * second ujprobe at the address - two ujprobes can't coexist
 */
static int add_new_uprobe(struct kprobe *old_p, struct kprobe *p)
{
	if (p->break_handler) {
		if (old_p->break_handler) {
			return -EEXIST;
		}

		list_add_tail_rcu(&p->list, &old_p->list);
		old_p->break_handler = aggr_break_uhandler;
	} else {
		list_add_rcu (&p->list, &old_p->list);
	}

	if (p->post_handler && !old_p->post_handler) {
		old_p->post_handler = aggr_post_uhandler;
	}

	return 0;
}

/*
 * Fill in the required fields of the "manager uprobe". Replace the
 * earlier uprobe in the hlist with the manager uprobe
 */
static inline void add_aggr_uprobe(struct kprobe *ap, struct kprobe *p)
{
	copy_uprobe(p, ap);

	ap->addr = p->addr;
	ap->pre_handler = aggr_pre_uhandler;
	ap->fault_handler = aggr_fault_uhandler;

	if (p->post_handler) {
		ap->post_handler = aggr_post_uhandler;
	}

	if (p->break_handler) {
		ap->break_handler = aggr_break_uhandler;
	}

	INIT_LIST_HEAD(&ap->list);
	list_add_rcu(&p->list, &ap->list);

	hlist_replace_rcu(&p->hlist, &ap->hlist);
}

/*
 * This is the second or subsequent uprobe at the address - handle
 * the intricacies
 */
static int register_aggr_uprobe(struct kprobe *old_p, struct kprobe *p)
{
	int ret = 0;
	struct kprobe *ap;

	if (old_p->pre_handler == aggr_pre_uhandler) {
		copy_uprobe(old_p, p);
		ret = add_new_uprobe(old_p, p);
	} else {
		ap = kzalloc(sizeof(*ap), GFP_KERNEL);
		if (!ap) {
			return -ENOMEM;
		}

		add_aggr_uprobe(ap, old_p);
		copy_uprobe(ap, p);
		ret = add_new_uprobe(ap, p);
	}

	return ret;
}

static void arm_uprobe(struct kprobe *p, struct task_struct *task)
{
	kprobe_opcode_t insn = BREAKPOINT_INSTRUCTION;

	if (!write_proc_vm_atomic(task, (unsigned long)p->addr, &insn, sizeof(insn))) {
		panic("arm_uprobe: failed to write memory %p!\n", p->addr);
	}
}

void disarm_uprobe(struct kprobe *p, struct task_struct *task)
{
	if (!write_proc_vm_atomic (task, (unsigned long) p->addr, &p->opcode, sizeof (p->opcode))) {
		panic("disarm_uprobe: failed to write memory: tgid=%u, addr=%p!\n", task->tgid, p->addr);
	}
}
EXPORT_SYMBOL_GPL(disarm_uprobe);

static void init_uprobes_insn_slots(void)
{
	int i;
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		INIT_HLIST_HEAD(&uprobe_insn_slot_table[i]);
	}
}

static void init_uprobe_table(void)
{
	int i;
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		INIT_HLIST_HEAD(&uprobe_table[i]);
	}
}

static void init_uretprobe_inst_table(void)
{
	int i;
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		INIT_HLIST_HEAD (&uretprobe_inst_table[i]);
	}
}

struct kprobe *get_uprobe(kprobe_opcode_t *addr, pid_t tgid)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;

	head = &uprobe_table[hash_ptr(addr, UPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(p, node, head, hlist) {
		if (p->addr == addr && p->tgid == tgid) {
			return p;
		}
	}

	return NULL;
}

static void add_uprobe_table(struct kprobe *p)
{
#ifdef CONFIG_ARM
	INIT_HLIST_NODE(&p->is_hlist_arm);
	hlist_add_head_rcu(&p->is_hlist_arm, &uprobe_insn_slot_table[hash_ptr(p->ainsn.insn_arm, UPROBE_HASH_BITS)]);
	INIT_HLIST_NODE(&p->is_hlist_thumb);
	hlist_add_head_rcu(&p->is_hlist_thumb, &uprobe_insn_slot_table[hash_ptr(p->ainsn.insn_thumb, UPROBE_HASH_BITS)]);
#else /* CONFIG_ARM */
	INIT_HLIST_NODE(&p->is_hlist);
	hlist_add_head_rcu(&p->is_hlist, &uprobe_insn_slot_table[hash_ptr(p->ainsn.insn, UPROBE_HASH_BITS)]);
#endif /* CONFIG_ARM */
}

#ifdef CONFIG_ARM
static struct kprobe *get_kprobe_by_insn_slot_arm(kprobe_opcode_t *addr, pid_t tgid)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *ret = NULL;

	/* TODO: test - two processes invokes instrumented function */
	head = &uprobe_insn_slot_table[hash_ptr(addr, UPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(p, node, head, is_hlist_arm) {
		if (p->ainsn.insn == addr && tgid == p->tgid) {
			ret = p;
			break;
		}
	}

	return ret;
}

static struct kprobe *get_kprobe_by_insn_slot_thumb(kprobe_opcode_t *addr, pid_t tgid)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *ret = NULL;

	/* TODO: test - two processes invokes instrumented function */
	head = &uprobe_insn_slot_table[hash_ptr(addr, UPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(p, node, head, is_hlist_thumb) {
		if (p->ainsn.insn == addr && tgid == p->tgid) {
			ret = p;
			break;
		}
	}

	return ret;
}

struct kprobe *get_kprobe_by_insn_slot(kprobe_opcode_t *addr, pid_t tgid, struct pt_regs *regs)
{
	struct kprobe *p = NULL;

	if (!thumb_mode(regs)) {
		p = get_kprobe_by_insn_slot_arm(addr - UPROBES_TRAMP_RET_BREAK_IDX, tgid);
	} else {
		p = get_kprobe_by_insn_slot_thumb((kprobe_opcode_t *)((unsigned long)addr - 0x1a), tgid);
	}

	return p;
}
#else /* CONFIG_ARM */
struct kprobe *get_kprobe_by_insn_slot(void *addr, int tgid, struct task_struct *ctask)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *ret = NULL;

	/* TODO: test - two processes invokes instrumented function */
	head = &uprobe_insn_slot_table[hash_ptr(addr, UPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(p, node, head, is_hlist) {
		if (p->ainsn.insn == addr && tgid == p->tgid) {
			ret = p;
			break;
		}
	}

	return ret;
}
#endif /* CONFIG_ARM */


static void remove_uprobe(struct kprobe *p, struct task_struct *task)
{
	if (p->tgid == 0) {
		panic("remove_uprobe for tgid == 0!!!");
	}

#ifdef CONFIG_ARM
	free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_arm);
	free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn_thumb);
#else /* CONFIG_ARM */
	free_insn_slot(&uprobe_insn_pages, task, p->ainsn.insn);
#endif /* CONFIG_ARM */
}

struct hlist_head *uretprobe_inst_table_head(void *hash_key)
{
	return &uretprobe_inst_table[hash_ptr (hash_key, UPROBE_HASH_BITS)];
}

/* Called with uretprobe_lock held */
static void add_urp_inst(struct kretprobe_instance *ri)
{
	/*
	 * Remove rp inst off the free list -
	 * Add it back when probed function returns
	 */
	hlist_del(&ri->uflist);

	/* Add rp inst onto table */
	INIT_HLIST_NODE(&ri->hlist);
	hlist_add_head(&ri->hlist, uretprobe_inst_table_head(ri->task->mm));

	/* Also add this rp inst to the used list. */
	INIT_HLIST_NODE(&ri->uflist);
	hlist_add_head(&ri->uflist, &ri->rp->used_instances);
}

/* Called with uretprobe_lock held */
void recycle_urp_inst(struct kretprobe_instance *ri)
{
	if (ri->rp) {
		hlist_del(&ri->hlist);
		/* remove rp inst off the used list */
		hlist_del(&ri->uflist);
		/* put rp inst back onto the free list */
		INIT_HLIST_NODE(&ri->uflist);
		hlist_add_head(&ri->uflist, &ri->rp->free_instances);
	}
}

/* Called with uretprobe_lock held */
static struct kretprobe_instance *get_used_urp_inst(struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;

	hlist_for_each_entry(ri, node, &rp->used_instances, uflist) {
		return ri;
	}

	return NULL;
}

/* Called with uretprobe_lock held */
struct kretprobe_instance *get_free_urp_inst_no_alloc (struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;

	hlist_for_each_entry (ri, node, &rp->free_instances, uflist) {
		return ri;
	}

	return NULL;
}

/* Called with uretprobe_lock held */
static void free_urp_inst(struct kretprobe *rp)
{
	struct kretprobe_instance *ri;
	while ((ri = get_free_urp_inst_no_alloc(rp)) != NULL) {
		hlist_del(&ri->uflist);
		kfree(ri);
	}
}

#define COMMON_URP_NR 10

static int alloc_nodes_uretprobe(struct kretprobe *rp)
{
	int alloc_nodes;
	struct kretprobe_instance *inst;
	int i;

#if 1//def CONFIG_PREEMPT
	rp->maxactive += max(COMMON_URP_NR, 2 * NR_CPUS);
#else
	rp->maxacpptive += NR_CPUS;
#endif
	alloc_nodes = COMMON_URP_NR;

	for (i = 0; i < alloc_nodes; ++i) {
		inst = kmalloc(sizeof(*inst), GFP_ATOMIC);
		if (inst == NULL) {
			free_urp_inst(rp);
			return -ENOMEM;
		}
		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	return 0;
}

/* Called with uretprobe_lock held */
static struct kretprobe_instance *get_free_urp_inst(struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;

	hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
		return ri;
	}

	if (!alloc_nodes_uretprobe(rp)) {
		hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
			return ri;
		}
	}

	return NULL;
}
// ===================================================================

int dbi_register_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
{
	int ret = 0;
	struct kprobe *old_p;

	if (!p->addr) {
		return -EINVAL;
	}

	DBPRINTF("p->addr = 0x%p p = 0x%p\n", p->addr, p);

// thumb address = address-1;
#if defined(CONFIG_ARM)
	// TODO: must be corrected in 'bundle'
	if ((unsigned long) p->addr & 0x01) {
		p->addr = (kprobe_opcode_t *)((unsigned long)p->addr & 0xfffffffe);
	}
#endif

	p->mod_refcounted = 0;
	p->nmissed = 0;
	INIT_LIST_HEAD(&p->list);
#ifdef KPROBES_PROFILE
	p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
	p->hnd_tm_sum.tv_sec = p->hnd_tm_sum.tv_usec = 0;
	p->count = 0;
#endif

	// get the first item
	old_p = get_uprobe(p->addr, p->tgid);
	if (old_p) {
#ifdef CONFIG_ARM
		p->safe_arm = old_p->safe_arm;
		p->safe_thumb = old_p->safe_thumb;
#endif
		ret = register_aggr_uprobe(old_p, p);
		if (!ret) {
//			atomic_inc(&kprobe_count);
			add_uprobe_table(p);
		}
		DBPRINTF("goto out\n", ret);
		goto out;
	}

	ret = arch_prepare_uprobe(p, task, atomic);
	if (ret) {
		DBPRINTF("goto out\n", ret);
		goto out;
	}

	DBPRINTF ("before out ret = 0x%x\n", ret);

	// TODO: add uprobe (must be in function)
	INIT_HLIST_NODE(&p->hlist);
	hlist_add_head_rcu(&p->hlist, &uprobe_table[hash_ptr(p->addr, UPROBE_HASH_BITS)]);
	add_uprobe_table(p);
	arm_uprobe(p, task);

out:
	DBPRINTF("out ret = 0x%x\n", ret);
	return ret;
}

void dbi_unregister_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
{
	struct kprobe *old_p, *list_p;
	int cleanup_p;

	old_p = get_uprobe(p->addr, p->tgid);
	if (unlikely(!old_p)) {
		return;
	}

	if (p != old_p) {
		list_for_each_entry_rcu(list_p, &old_p->list, list) {
			if (list_p == p) {
				/* uprobe p is a valid probe */
				goto valid_p;
			}
		}

		return;
	}

valid_p:
	if ((old_p == p) || ((old_p->pre_handler == aggr_pre_uhandler) &&
	    (p->list.next == &old_p->list) && (p->list.prev == &old_p->list))) {
		/* Only probe on the hash list */
		disarm_uprobe(p, task);
		hlist_del_rcu(&old_p->hlist);
		cleanup_p = 1;
	} else {
		list_del_rcu(&p->list);
		cleanup_p = 0;
	}

	if (cleanup_p) {
		if (p != old_p) {
			list_del_rcu(&p->list);
			kfree(old_p);
		}

		if (!in_atomic()) {
			synchronize_sched();
		}

		remove_uprobe(p, task);
	} else {
		if (p->break_handler) {
			old_p->break_handler = NULL;
		}

		if (p->post_handler) {
			list_for_each_entry_rcu (list_p, &old_p->list, list) {
				if (list_p->post_handler) {
					cleanup_p = 2;
					break;
				}
			}

			if (cleanup_p == 0) {
				old_p->post_handler = NULL;
			}
		}
	}
}

int dbi_register_ujprobe(struct task_struct *task, struct jprobe *jp, int atomic)
{
	int ret = 0;

	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_upre_handler;
	jp->kp.break_handler = longjmp_break_uhandler;

	ret = dbi_register_uprobe(&jp->kp, task, atomic);

	return ret;
}

void dbi_unregister_ujprobe(struct task_struct *task, struct jprobe *jp, int atomic)
{
	dbi_unregister_uprobe(&jp->kp, task, atomic);
	/*
	 * Here is an attempt to unregister even those probes that have not been
	 * installed (hence not added to the hlist).
	 * So if we try to delete them from the hlist we will get NULL pointer
	 * dereference error. That is why we check whether this node
	 * really belongs to the hlist.
	 */
#ifdef CONFIG_ARM
	if (!(hlist_unhashed(&jp->kp.is_hlist_arm))) {
		hlist_del_rcu(&jp->kp.is_hlist_arm);
	}
	if (!(hlist_unhashed(&jp->kp.is_hlist_thumb))) {
		hlist_del_rcu(&jp->kp.is_hlist_thumb);
	}
#else /* CONFIG_ARM */
	if (!(hlist_unhashed(&jp->kp.is_hlist))) {
		hlist_del_rcu(&jp->kp.is_hlist);
	}
#endif /* CONFIG_ARM */
}

static int pre_handler_uretprobe(struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe *rp = container_of(p, struct kretprobe, kp);
	struct kretprobe_instance *ri;
	unsigned long flags;

	/* TODO: consider to only swap the RA after the last pre_handler fired */
	spin_lock_irqsave(&uretprobe_lock, flags);
	if (rp->disarm) {
		goto unlock;
	}

	/* TODO: test - remove retprobe after func entry but before its exit */
	if ((ri = get_free_urp_inst(rp)) != NULL) {
		ri->rp = rp;
		ri->rp2 = NULL;
		ri->task = current;

		arch_prepare_uretprobe_hl(ri, regs);

		add_urp_inst(ri);
	} else {
		++rp->nmissed;
	}

unlock:
	spin_unlock_irqrestore(&uretprobe_lock, flags);

	return 0;
}

int dbi_register_uretprobe(struct task_struct *task, struct kretprobe *rp, int atomic)
{
	int i, ret = 0;
	struct kretprobe_instance *inst;

	DBPRINTF ("START\n");

	rp->kp.pre_handler = pre_handler_uretprobe;
	rp->kp.post_handler = NULL;
	rp->kp.fault_handler = NULL;
	rp->kp.break_handler = NULL;

	rp->disarm = 0;

	/* Pre-allocate memory for max kretprobe instances */
	if (rp->maxactive <= 0) {
#if 1//def CONFIG_PREEMPT
		rp->maxactive = max(10, 2 * NR_CPUS);
#else
		rp->maxactive = NR_CPUS;
#endif
	}

	INIT_HLIST_HEAD(&rp->used_instances);
	INIT_HLIST_HEAD(&rp->free_instances);

	for (i = 0; i < rp->maxactive; i++) {
		inst = kmalloc(sizeof(*inst), GFP_KERNEL);
		if (inst == NULL) {
			free_urp_inst(rp);
			ret = -ENOMEM;
			goto out;
		}

		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	rp->nmissed = 0;

	/* Establish function entry probe point */
	ret = dbi_register_uprobe(&rp->kp, task, atomic);
	if (ret) {
		free_urp_inst(rp);
		goto out;
	}

out:
	return ret;
}

int dbi_disarm_urp_inst(struct kretprobe_instance *ri, struct task_struct *rm_task)
{
	struct task_struct *task = rm_task ? rm_task : ri->task;
	kprobe_opcode_t *tramp;
	kprobe_opcode_t *sp = (kprobe_opcode_t *)((long)ri->sp & ~1);
	kprobe_opcode_t *stack = sp - RETPROBE_STACK_DEPTH + 1;
	kprobe_opcode_t *found = NULL;
	kprobe_opcode_t *buf[RETPROBE_STACK_DEPTH];
	int i, retval;

	/* Understand function mode */
	if ((long)ri->sp & 1) {
		tramp = (kprobe_opcode_t *)
			((unsigned long)ri->rp->kp.ainsn.insn + 0x1b);
	} else {
		tramp = (kprobe_opcode_t *)
			(ri->rp->kp.ainsn.insn + UPROBES_TRAMP_RET_BREAK_IDX);
	}

	retval = read_proc_vm_atomic(task, (unsigned long)stack, buf, sizeof(buf));
	if (retval != sizeof(buf)) {
		printk("---> %s (%d/%d): failed to read stack from %08lx",
			task->comm, task->tgid, task->pid, (unsigned long)stack);
		retval = -EFAULT;
		goto out;
	}

	/* search the stack from the bottom */
	for (i = RETPROBE_STACK_DEPTH - 1; i >= 0; i--) {
		if (buf[i] == tramp) {
			found = stack + i;
			break;
		}
	}

	if (found) {
		printk("---> %s (%d/%d): trampoline found at %08lx (%08lx /%+d) - %p\n",
				task->comm, task->tgid, task->pid,
				(unsigned long)found, (unsigned long)sp,
				found - sp, ri->rp->kp.addr);
		retval = write_proc_vm_atomic(task, (unsigned long)found, &ri->ret_addr,
				sizeof(ri->ret_addr));
		if (retval != sizeof(ri->ret_addr)) {
			printk("---> %s (%d/%d): failed to write value to %08lx",
				task->comm, task->tgid, task->pid, (unsigned long)found);
			retval = -EFAULT;
		} else {
			retval = 0;
		}
	} else {
		struct pt_regs *uregs = task_pt_regs(ri->task);
		unsigned long ra = dbi_get_ret_addr(uregs);
		if (ra == (unsigned long)tramp) {
			printk("---> %s (%d/%d): trampoline found at lr = %08lx - %p\n",
					task->comm, task->tgid, task->pid, ra, ri->rp->kp.addr);
			dbi_set_ret_addr(uregs, (unsigned long)tramp);
			retval = 0;
		} else {
			printk("---> %s (%d/%d): trampoline NOT found at sp = %08lx, lr = %08lx - %p\n",
					task->comm, task->tgid, task->pid,
					(unsigned long)sp, ra, ri->rp->kp.addr);
			retval = -ENOENT;
		}
	}

out:
	return retval;
}

/* Called with uretprobe_lock held */
int dbi_disarm_urp_inst_for_task(struct task_struct *parent, struct task_struct *task)
{
	struct kretprobe_instance *ri;
	struct hlist_node *node, *tmp;
	struct hlist_head *head = uretprobe_inst_table_head(parent->mm);

	hlist_for_each_entry_safe(ri, node, tmp, head, hlist) {
		if (parent == ri->task && ri->rp->kp.tgid) {
			dbi_disarm_urp_inst(ri, task);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(dbi_disarm_urp_inst_for_task);

void dbi_unregister_uretprobe(struct task_struct *task, struct kretprobe *rp, int atomic, int not_rp2)
{
	unsigned long flags;
	struct kretprobe_instance *ri;
	struct kretprobe *rp2 = NULL;

	spin_lock_irqsave (&uretprobe_lock, flags);

	while ((ri = get_used_urp_inst(rp)) != NULL) {
		if (dbi_disarm_urp_inst(ri, NULL) != 0)
			/*panic*/printk("%s (%d/%d): cannot disarm urp instance (%08lx)\n",
					ri->task->comm, ri->task->tgid, ri->task->pid,
					(unsigned long)rp->kp.addr);
		recycle_urp_inst(ri);
	}

	if (hlist_empty(&rp->used_instances) || not_rp2) {
		struct kprobe *p = &rp->kp;
#ifdef CONFIG_ARM
		if (!(hlist_unhashed(&p->is_hlist_arm))) {
			hlist_del_rcu(&p->is_hlist_arm);
		}

		if (!(hlist_unhashed(&p->is_hlist_thumb))) {
			hlist_del_rcu(&p->is_hlist_thumb);
		}
#else /* CONFIG_ARM */
		if (!(hlist_unhashed(&p->is_hlist))) {
			hlist_del_rcu(&p->is_hlist);
		}
#endif /* CONFIG_ARM */
	} else {
		struct kprobe *new_p = NULL;
		struct kprobe *p = &rp->kp;
		rp2 = clone_kretprobe(rp);
		if (!rp2) {
			DBPRINTF ("dbi_unregister_uretprobe addr %p: failed to clone retprobe!", rp->kp.addr);
		} else {
			DBPRINTF ("initiating deferred retprobe deletion addr %p", rp->kp.addr);
			printk ("initiating deferred retprobe deletion addr %p\n", rp->kp.addr);
			disarm_uprobe(&rp->kp, task);
			rp2->disarm = 1;
		}
		/*
		 * As we cloned retprobe we have to update the entry in the insn slot
		 * hash list.
		 */
#ifdef CONFIG_ARM
		if (!(hlist_unhashed(&p->is_hlist_arm))) {
			hlist_del_rcu(&p->is_hlist_arm);
		}
		if (!(hlist_unhashed(&p->is_hlist_thumb))) {
			hlist_del_rcu(&p->is_hlist_thumb);
		}
#else /* CONFIG_ARM */
		if (!(hlist_unhashed(&p->is_hlist))) {
			hlist_del_rcu(&p->is_hlist);
		}
#endif /* CONFIG_ARM */
		new_p = &rp2->kp;
		add_uprobe_table(new_p);
	}

	while ((ri = get_used_urp_inst(rp)) != NULL) {
		ri->rp = NULL;
		ri->rp2 = rp2;
		hlist_del(&ri->uflist);
	}

	spin_unlock_irqrestore(&uretprobe_lock, flags);
	free_urp_inst(rp);

	dbi_unregister_uprobe(&rp->kp, task, atomic);
}

void dbi_unregister_all_uprobes(struct task_struct *task, int atomic)
{
	struct hlist_head *head;
	struct hlist_node *node, *tnode;
	struct kprobe *p;
	int i;

	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		head = &uprobe_table[i];
		hlist_for_each_entry_safe(p, node, tnode, head, hlist) {
			if (p->tgid == task->tgid) {
				printk("dbi_unregister_all_uprobes: delete uprobe at %p[%lx] for %s/%d\n",
						p->addr, (unsigned long)p->opcode, task->comm, task->pid);
				dbi_unregister_uprobe(p, task, atomic);
			}
		}
	}
}

void dbi_uprobe_return(void)
{
	dbi_arch_uprobe_return();
}

static int __init init_uprobes(void)
{
	init_uprobe_table();
	init_uprobes_insn_slots();
	init_uretprobe_inst_table();

	return swap_arch_init_uprobes();
}

static void __exit exit_uprobes(void)
{
	swap_arch_exit_uprobes();
}

EXPORT_SYMBOL_GPL(dbi_uprobe_return);
EXPORT_SYMBOL_GPL(dbi_register_ujprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_ujprobe);
EXPORT_SYMBOL_GPL(dbi_register_uretprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_uretprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_all_uprobes);

module_init(init_uprobes);
module_exit(exit_uprobes);

MODULE_LICENSE ("GPL");
