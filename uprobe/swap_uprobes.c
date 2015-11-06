/**
 * uprobe/swap_uprobes.c
 * @author Alexey Gerenkov <a.gerenkov@samsung.com> User-Space Probes initial
 * implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * @author Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for
 * separating core and arch parts
 *
 * @section LICENSE
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
 * @section COPYRIGHT
 *
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * @section DESCRIPTION
 *
 * Uprobes implementation.
 */


#include <linux/hash.h>
#include <linux/mempolicy.h>
#include <linux/module.h>

#include <master/swap_initializer.h>
#include <kprobe/swap_slots.h>
#include <kprobe/swap_kdebug.h>
#include <kprobe/swap_kprobes_deps.h>

#include <swap-asm/swap_uprobes.h>

#include "swap_uprobes.h"


enum {
	UPROBE_HASH_BITS  = 10,
	UPROBE_TABLE_SIZE = (1 << UPROBE_HASH_BITS)
};

static DEFINE_RWLOCK(st_lock);
static struct hlist_head slot_table[UPROBE_TABLE_SIZE];
struct hlist_head uprobe_table[UPROBE_TABLE_SIZE];

DEFINE_SPINLOCK(uretprobe_lock);	/* Protects uretprobe_inst_table */
static struct hlist_head uretprobe_inst_table[UPROBE_TABLE_SIZE];

#define DEBUG_PRINT_HASH_TABLE 0

#if DEBUG_PRINT_HASH_TABLE
void print_uprobe_hash_table(void)
{
	int i;
	struct hlist_head *head;
	struct uprobe *p;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	/* print uprobe table */
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		head = &uprobe_insn_slot_table[i];
		swap_hlist_for_each_entry_rcu(p, node, head, is_hlist) {
			printk(KERN_INFO "####### find U tgid=%u, addr=0x%lx\n",
					p->task->tgid, (unsigned long)p->addr);
		}
	}
}
#endif


struct uinst_info *uinst_info_create(unsigned long vaddr,
				     kprobe_opcode_t opcode)
{
	struct uinst_info *uinst;

	uinst = kmalloc(sizeof(*uinst), GFP_ATOMIC);
	if (uinst) {
		INIT_HLIST_NODE(&uinst->hlist);
		uinst->vaddr = vaddr;
		uinst->opcode = opcode;
	} else {
		pr_err("Cannot allocate memory for uinst\n");
	}

	return uinst;
}
EXPORT_SYMBOL_GPL(uinst_info_create);

void uinst_info_destroy(struct uinst_info *uinst)
{
	kfree(uinst);
}
EXPORT_SYMBOL_GPL(uinst_info_destroy);

void uinst_info_disarm(struct uinst_info *uinst, struct task_struct *task)
{
	struct uprobe p;

	p.addr = (uprobe_opcode_t *)uinst->vaddr;
	p.opcode = uinst->opcode;
	arch_disarm_uprobe(&p, task);
}
EXPORT_SYMBOL_GPL(uinst_info_disarm);

/*
 * Keep all fields in the uprobe consistent
 */
static inline void copy_uprobe(struct uprobe *old_p, struct uprobe *p)
{
	memcpy(&p->opcode, &old_p->opcode, sizeof(uprobe_opcode_t));
	memcpy(&p->ainsn, &old_p->ainsn, sizeof(struct arch_insn));
}

/*
 * Aggregate handlers for multiple uprobes support - these handlers
 * take care of invoking the individual uprobe handlers on p->list
 */
static int aggr_pre_uhandler(struct uprobe *p, struct pt_regs *regs)
{
	struct uprobe *up;
	int ret;

	list_for_each_entry_rcu(up, &p->list, list) {
		if (up->pre_handler) {
			ret = up->pre_handler(up, regs);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static void aggr_post_uhandler(struct uprobe *p, struct pt_regs *regs,
			       unsigned long flags)
{
	struct uprobe *up;

	list_for_each_entry_rcu(up, &p->list, list) {
		if (up->post_handler)
			up->post_handler(up, regs, flags);
	}
}

static int aggr_fault_uhandler(struct uprobe *p,
			       struct pt_regs *regs,
			       int trapnr)
{
	return 0;
}

static int aggr_break_uhandler(struct uprobe *p, struct pt_regs *regs)
{
	return 0;
}

/*
 * Add the new probe to old_p->list. Fail if this is the
 * second ujprobe at the address - two ujprobes can't coexist
 */
static int add_new_uprobe(struct uprobe *old_p, struct uprobe *p)
{
	if (p->break_handler) {
		if (old_p->break_handler)
			return -EEXIST;

		list_add_tail_rcu(&p->list, &old_p->list);
		old_p->break_handler = aggr_break_uhandler;
	} else {
		list_add_rcu(&p->list, &old_p->list);
	}

	if (p->post_handler && !old_p->post_handler)
		old_p->post_handler = aggr_post_uhandler;

	return 0;
}

/*
 * Fill in the required fields of the "manager uprobe". Replace the
 * earlier uprobe in the hlist with the manager uprobe
 */
static inline void add_aggr_uprobe(struct uprobe *ap, struct uprobe *p)
{
	copy_uprobe(p, ap);

	ap->addr = p->addr;
	ap->pre_handler = aggr_pre_uhandler;
	ap->fault_handler = aggr_fault_uhandler;

	if (p->post_handler)
		ap->post_handler = aggr_post_uhandler;

	if (p->break_handler)
		ap->break_handler = aggr_break_uhandler;

	INIT_LIST_HEAD(&ap->list);
	list_add_rcu(&p->list, &ap->list);

	hlist_replace_rcu(&p->hlist, &ap->hlist);
}

/*
 * This is the second or subsequent uprobe at the address - handle
 * the intricacies
 */
static int register_aggr_uprobe(struct uprobe *old_p, struct uprobe *p)
{
	int ret = 0;

	if (old_p->pre_handler == aggr_pre_uhandler) {
		copy_uprobe(old_p, p);
		ret = add_new_uprobe(old_p, p);
	} else {
		struct uprobe *uap = kzalloc(sizeof(*uap), GFP_KERNEL);
		if (!uap)
			return -ENOMEM;

		uap->task = p->task;
		add_aggr_uprobe(uap, old_p);
		copy_uprobe(uap, p);
		ret = add_new_uprobe(uap, p);
	}

	return ret;
}

static int arm_uprobe(struct uprobe *p)
{
	return arch_arm_uprobe(p);
}

/**
 * @brief Disarms uprobe.
 *
 * @param p Pointer to the uprobe.
 * @param task Pointer to the target task.
 * @return Void.
 */
void disarm_uprobe(struct uprobe *p, struct task_struct *task)
{
	arch_disarm_uprobe(p, task);
}
EXPORT_SYMBOL_GPL(disarm_uprobe);

static void init_uprobes_insn_slots(void)
{
	int i;
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i)
		INIT_HLIST_HEAD(&slot_table[i]);
}

static void init_uprobe_table(void)
{
	int i;
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i)
		INIT_HLIST_HEAD(&uprobe_table[i]);
}

static void init_uretprobe_inst_table(void)
{
	int i;
	for (i = 0; i < UPROBE_TABLE_SIZE; ++i)
		INIT_HLIST_HEAD(&uretprobe_inst_table[i]);
}

/**
 * @brief Gets uprobe.
 *
 * @param addr Probe's address.
 * @param tgid Probes's thread group ID.
 * @return Pointer to the uprobe on success,\n
 * NULL otherwise.
 */
struct uprobe *get_uprobe(void *addr, pid_t tgid)
{
	struct hlist_head *head;
	struct uprobe *p;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	head = &uprobe_table[hash_ptr(addr, UPROBE_HASH_BITS)];
	swap_hlist_for_each_entry_rcu(p, node, head, hlist) {
		if (p->addr == addr && p->task->tgid == tgid)
			return p;
	}

	return NULL;
}

/**
 * @brief Adds uprobe to hlist when trampoline have been made.
 *
 * @param p Pointer to the uprobe.
 * @return Void.
 */
void add_uprobe_table(struct uprobe *p)
{
	write_lock(&st_lock);
	hlist_add_head(&p->is_hlist,
		       &slot_table[hash_ptr(p->ainsn.insn, UPROBE_HASH_BITS)]);
	write_unlock(&st_lock);
}

static void del_uprobe_table(struct uprobe *p)
{
	write_lock(&st_lock);
	if (!hlist_unhashed(&p->is_hlist))
		hlist_del(&p->is_hlist);
	write_unlock(&st_lock);
}

/**
 * @brief Gets uprobe by insn slot.
 *
 * @param addr Probe's address.
 * @param tgit Probe's thread group ID.
 * @param regs Pointer to CPU registers data.
 * @return Pointer to the uprobe on success,\n
 * NULL otherwise.
 */
struct uprobe *get_uprobe_by_insn_slot(void *addr,
				       pid_t tgid,
				       struct pt_regs *regs)
{
	struct hlist_head *head;
	struct uprobe *p;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	read_lock(&st_lock);
	head = &slot_table[hash_ptr(addr, UPROBE_HASH_BITS)];
	swap_hlist_for_each_entry(p, node, head, is_hlist) {
		if (p->ainsn.insn == addr && p->task->tgid == tgid) {
			read_unlock(&st_lock);
			return p;
		}
	}
	read_unlock(&st_lock);

	return NULL;
}


static void remove_uprobe(struct uprobe *up)
{
	del_uprobe_table(up);
	arch_remove_uprobe(up);
}

static struct hlist_head *uretprobe_inst_table_head(void *hash_key)
{
	return &uretprobe_inst_table[hash_ptr(hash_key, UPROBE_HASH_BITS)];
}

/* Called with uretprobe_lock held */
static void add_urp_inst(struct uretprobe_instance *ri)
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
static void recycle_urp_inst(struct uretprobe_instance *ri)
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
static struct uretprobe_instance *get_used_urp_inst(struct uretprobe *rp)
{
	struct uretprobe_instance *ri;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	swap_hlist_for_each_entry(ri, node, &rp->used_instances, uflist) {
		return ri;
	}

	return NULL;
}

/**
 * @brief Gets free uretprobe instanse for the specified uretprobe without
 * allocation. Called with uretprobe_lock held.
 *
 * @param rp Pointer to the uretprobe.
 * @return Pointer to the uretprobe_instance on success,\n
 * NULL otherwise.
 */
struct uretprobe_instance *get_free_urp_inst_no_alloc(struct uretprobe *rp)
{
	struct uretprobe_instance *ri;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	swap_hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
		return ri;
	}

	return NULL;
}

/* Called with uretprobe_lock held */
static void free_urp_inst(struct uretprobe *rp)
{
	struct uretprobe_instance *ri;
	while ((ri = get_free_urp_inst_no_alloc(rp)) != NULL) {
		hlist_del(&ri->uflist);
		kfree(ri);
	}
}

#define COMMON_URP_NR 10

static int alloc_nodes_uretprobe(struct uretprobe *rp)
{
	int alloc_nodes;
	struct uretprobe_instance *inst;
	int i;

#if 1 /* def CONFIG_PREEMPT */
	rp->maxactive += max(COMMON_URP_NR, 2 * NR_CPUS);
#else
	rp->maxacpptive += NR_CPUS;
#endif
	alloc_nodes = COMMON_URP_NR;

	for (i = 0; i < alloc_nodes; ++i) {
		inst = kmalloc(sizeof(*inst) + rp->data_size, GFP_ATOMIC);
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
static struct uretprobe_instance *get_free_urp_inst(struct uretprobe *rp)
{
	struct uretprobe_instance *ri;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	swap_hlist_for_each_entry(ri, node, &rp->free_instances, uflist) {
		return ri;
	}

	if (!alloc_nodes_uretprobe(rp)) {
		swap_hlist_for_each_entry(ri, node,
					  &rp->free_instances, uflist) {
			return ri;
		}
	}

	return NULL;
}
/* =================================================================== */

/**
 * @brief Registers uprobe.
 *
 * @param up Pointer to the uprobe to register.
 * @return 0 on success,\n
 * negative error code on error.
 */
int swap_register_uprobe(struct uprobe *p)
{
	int ret = 0;
	struct uprobe *old_p;

	if (!p->addr)
		return -EINVAL;

	p->ainsn.insn = NULL;
	INIT_LIST_HEAD(&p->list);
#ifdef KPROBES_PROFILE
	p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
	p->hnd_tm_sum.tv_sec = p->hnd_tm_sum.tv_usec = 0;
	p->count = 0;
#endif

	/* get the first item */
	old_p = get_uprobe(p->addr, p->task->tgid);
	if (old_p) {
		struct task_struct *task = p->task;

		/* TODO: add support many uprobes on address */
		printk(KERN_INFO "uprobe on task[%u %u %s] vaddr=%p is there\n",
		       task->tgid, task->pid, task->comm, p->addr);
		ret = -EINVAL;
		goto out;

		ret = register_aggr_uprobe(old_p, p);
		DBPRINTF("goto out\n", ret);
		goto out;
	}

	INIT_HLIST_NODE(&p->is_hlist);

	ret = arch_prepare_uprobe(p);
	if (ret) {
		DBPRINTF("goto out\n", ret);
		goto out;
	}

	DBPRINTF("before out ret = 0x%x\n", ret);

	/* TODO: add uprobe (must be in function) */
	INIT_HLIST_NODE(&p->hlist);
	hlist_add_head_rcu(&p->hlist,
			   &uprobe_table[hash_ptr(p->addr, UPROBE_HASH_BITS)]);

	ret = arm_uprobe(p);
	if (ret) {
		hlist_del_rcu(&p->hlist);
		synchronize_rcu();
		remove_uprobe(p);
	}

out:
	DBPRINTF("out ret = 0x%x\n", ret);
	return ret;
}
EXPORT_SYMBOL_GPL(swap_register_uprobe);

/**
 * @brief Unregisters uprobe.
 *
 * @param up Pointer to the uprobe.
 * @param disarm Disarm flag. When true uprobe is disarmed.
 * @return Void.
 */
void __swap_unregister_uprobe(struct uprobe *p, int disarm)
{
	struct uprobe *old_p, *list_p;
	int cleanup_p;

	/* we MUST check probe for uncreated process  */
	if (!p->task)
		return;

	old_p = get_uprobe(p->addr, p->task->tgid);
	if (unlikely(!old_p))
		return;

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
		if (disarm)
			disarm_uprobe(p, p->task);

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

		if (!in_atomic())
			synchronize_sched();

		remove_uprobe(p);
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
EXPORT_SYMBOL_GPL(__swap_unregister_uprobe);

/**
 * @brief Unregisters uprobe. Main interface function, wrapper for
 * __swap_unregister_uprobe.
 *
 * @param up Pointer to the uprobe.
 * @return Void.
 */
void swap_unregister_uprobe(struct uprobe *up)
{
	__swap_unregister_uprobe(up, 1);
}

/**
 * @brief Registers ujprobe.
 *
 * @param uj Pointer to the ujprobe function.
 * @return 0 on success,\n
 * error code on error.
 */
int swap_register_ujprobe(struct ujprobe *jp)
{
	int ret = 0;

	/* Todo: Verify probepoint is a function entry point */
	jp->up.pre_handler = setjmp_upre_handler;
	jp->up.break_handler = longjmp_break_uhandler;

	ret = swap_register_uprobe(&jp->up);

	return ret;
}
EXPORT_SYMBOL_GPL(swap_register_ujprobe);

/**
 * @brief Unregisters ujprobe.
 *
 * @param jp Pointer to the ujprobe.
 * @param disarm Disarm flag, passed to __swap_unregister_uprobe.
 * @return Void.
 */
void __swap_unregister_ujprobe(struct ujprobe *jp, int disarm)
{
	__swap_unregister_uprobe(&jp->up, disarm);
}
EXPORT_SYMBOL_GPL(__swap_unregister_ujprobe);

/**
 * @brief Unregisters ujprobe. Main interface function, wrapper for
 * __swap_unregister_ujprobe.
 *
 * @param jp Pointer to the jprobe.
 * @return Void.
 */
void swap_unregister_ujprobe(struct ujprobe *jp)
{
	__swap_unregister_ujprobe(jp, 1);
}
EXPORT_SYMBOL_GPL(swap_unregister_ujprobe);

/**
 * @brief Trampoline uprobe handler.
 *
 * @param p Pointer to the uprobe.
 * @param regs Pointer to CPU register data.
 * @return 1
 */
int trampoline_uprobe_handler(struct uprobe *p, struct pt_regs *regs)
{
	struct uretprobe_instance *ri = NULL;
	struct uprobe *up;
	struct hlist_head *head;
	unsigned long flags, tramp_addr, orig_ret_addr = 0;
	struct hlist_node *tmp;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	tramp_addr = arch_get_trampoline_addr(p, regs);
	spin_lock_irqsave(&uretprobe_lock, flags);

	head = uretprobe_inst_table_head(current->mm);

	/*
	 * It is possible to have multiple instances associated with a given
	 * task either because an multiple functions in the call path
	 * have a return probe installed on them, and/or more then one
	 * return probe was registered for a target function.
	 *
	 * We can handle this because:
	 *     - instances are always inserted at the head of the list
	 *     - when multiple return probes are registered for the same
	 *       function, the first instance's ret_addr will point to the
	 *       real return address, and all the rest will point to
	 *       uretprobe_trampoline
	 */
	swap_hlist_for_each_entry_safe(ri, node, tmp, head, hlist) {
		if (ri->task != current) {
			/* another task is sharing our hash bucket */
			continue;
		}

		up = NULL;
		if (ri->rp) {
			up = &ri->rp->up;

			if (ri->rp->handler)
				ri->rp->handler(ri, regs);
		}

		orig_ret_addr = (unsigned long)ri->ret_addr;
		recycle_urp_inst(ri);

		if ((orig_ret_addr != tramp_addr && up == p) || up == NULL) {
			/*
			 * This is the real return address. Any other
			 * instances associated with this task are for
			 * other calls deeper on the call stack
			 */
			break;
		}
	}

	spin_unlock_irqrestore(&uretprobe_lock, flags);
	/* orig_ret_addr is NULL when there is no need to restore anything
	 * (all the magic is performed inside handler) */
	if (likely(orig_ret_addr))
		arch_set_orig_ret_addr(orig_ret_addr, regs);

	return 1;
}

static int pre_handler_uretprobe(struct uprobe *p, struct pt_regs *regs)
{
	struct uretprobe *rp = container_of(p, struct uretprobe, up);
#ifdef CONFIG_ARM
	int noret = thumb_mode(regs) ? rp->thumb_noret : rp->arm_noret;
#endif
	struct uretprobe_instance *ri;
	unsigned long flags;

#ifdef CONFIG_ARM
	if (noret)
		return 0;
#endif

	/* TODO: consider to only swap the
	 * RA after the last pre_handler fired */
	spin_lock_irqsave(&uretprobe_lock, flags);

	/* TODO: test - remove retprobe after func entry but before its exit */
	ri = get_free_urp_inst(rp);
	if (ri != NULL) {
		int ret;

		ri->rp = rp;
		ri->task = current;
#ifdef CONFIG_ARM
		ri->preload_thumb = 0;
#endif

		if (rp->entry_handler)
			rp->entry_handler(ri, regs);

		ret = arch_prepare_uretprobe(ri, regs);
		add_urp_inst(ri);
		if (ret) {
			recycle_urp_inst(ri);
			++rp->nmissed;
		}
	} else {
		++rp->nmissed;
	}

	spin_unlock_irqrestore(&uretprobe_lock, flags);

	return 0;
}

/**
 * @brief Registers uretprobe.
 *
 * @param rp Pointer to the uretprobe.
 * @return 0 on success,\n
 * negative error code on error.
 */
int swap_register_uretprobe(struct uretprobe *rp)
{
	int i, ret = 0;
	struct uretprobe_instance *inst;

	DBPRINTF("START\n");

	rp->up.pre_handler = pre_handler_uretprobe;
	rp->up.post_handler = NULL;
	rp->up.fault_handler = NULL;
	rp->up.break_handler = NULL;

	/* Pre-allocate memory for max kretprobe instances */
	if (rp->maxactive <= 0) {
#if 1 /* def CONFIG_PREEMPT */
		rp->maxactive = max(10, 2 * NR_CPUS);
#else
		rp->maxactive = NR_CPUS;
#endif
	}

	INIT_HLIST_HEAD(&rp->used_instances);
	INIT_HLIST_HEAD(&rp->free_instances);

	for (i = 0; i < rp->maxactive; i++) {
		inst = kmalloc(sizeof(*inst) + rp->data_size, GFP_KERNEL);
		if (inst == NULL) {
			free_urp_inst(rp);
			return -ENOMEM;
		}

		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	rp->nmissed = 0;

	/* Establish function entry probe point */
	ret = swap_register_uprobe(&rp->up);
	if (ret)
		return ret;

	arch_opcode_analysis_uretprobe(rp);

	return 0;
}
EXPORT_SYMBOL_GPL(swap_register_uretprobe);

/**
 * @brief Unregisters uretprobe.
 *
 * @param rp Pointer to the ureprobe.
 * @param disarm Disarm flag, passed to __swap_unregister_uprobe
 * @return Void.
 */
void __swap_unregister_uretprobe(struct uretprobe *rp, int disarm)
{
	unsigned long flags;
	struct uretprobe_instance *ri;

	__swap_unregister_uprobe(&rp->up, disarm);

	spin_lock_irqsave(&uretprobe_lock, flags);
	while ((ri = get_used_urp_inst(rp)) != NULL) {
		bool is_current = ri->task == current;

		if (is_current)
			spin_unlock_irqrestore(&uretprobe_lock, flags);

		/* FIXME: arch_disarm_urp_inst() for no current context */
		if (arch_disarm_urp_inst(ri, ri->task, 0) != 0)
			printk(KERN_INFO "%s (%d/%d): "
			       "cannot disarm urp instance (%08lx)\n",
			       ri->task->comm, ri->task->tgid, ri->task->pid,
			       (unsigned long)rp->up.addr);

		if (is_current)
			spin_lock_irqsave(&uretprobe_lock, flags);

		recycle_urp_inst(ri);
	}

	while ((ri = get_used_urp_inst(rp)) != NULL) {
		ri->rp = NULL;
		hlist_del(&ri->uflist);
	}
	spin_unlock_irqrestore(&uretprobe_lock, flags);

	free_urp_inst(rp);
}
EXPORT_SYMBOL_GPL(__swap_unregister_uretprobe);

/**
 * @brief Unregistets uretprobe. Main interface function, wrapper for
 * __swap_unregister_uretprobe.
 *
 * @param rp Pointer to the uretprobe.
 * @return Void.
 */
void swap_unregister_uretprobe(struct uretprobe *rp)
{
	__swap_unregister_uretprobe(rp, 1);
}
EXPORT_SYMBOL_GPL(swap_unregister_uretprobe);

/**
 * @brief Unregisters all uprobes for task's thread group ID.
 *
 * @param task Pointer to the task_struct
 * @return Void.
 */
void swap_unregister_all_uprobes(struct task_struct *task)
{
	struct hlist_head *head;
	struct uprobe *p;
	int i;
	struct hlist_node *tnode;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	for (i = 0; i < UPROBE_TABLE_SIZE; ++i) {
		head = &uprobe_table[i];
		swap_hlist_for_each_entry_safe(p, node, tnode, head, hlist) {
			if (p->task->tgid == task->tgid) {
				printk(KERN_INFO "%s: delete uprobe at %p[%lx]"
				       " for %s/%d\n", __func__, p->addr,
				       (unsigned long)p->opcode,
				       task->comm, task->pid);
				swap_unregister_uprobe(p);
			}
		}
	}
}
EXPORT_SYMBOL_GPL(swap_unregister_all_uprobes);

/**
 * @brief Arch-independent wrapper for arch_ujprobe_return.
 *
 * @return Void.
 */
void swap_ujprobe_return(void)
{
	arch_ujprobe_return();
}
EXPORT_SYMBOL_GPL(swap_ujprobe_return);


static struct urinst_info *urinst_info_create(struct uretprobe_instance *ri)
{
	struct urinst_info *urinst;

	urinst = kmalloc(sizeof(*urinst), GFP_ATOMIC);
	if (urinst) {
		INIT_HLIST_NODE(&urinst->hlist);
		urinst->task = ri->task;
		urinst->sp = (unsigned long)ri->sp;
		urinst->tramp = arch_tramp_by_ri(ri);
		urinst->ret_addr = (unsigned long)ri->ret_addr;
	} else {
		pr_err("Cannot allocate memory for urinst\n");
	}

	return urinst;
}

static void urinst_info_destroy(struct urinst_info *urinst)
{
	kfree(urinst);
}

static void urinst_info_disarm(struct urinst_info *urinst, struct task_struct *task)
{
	struct uretprobe_instance ri;
	unsigned long tramp = urinst->tramp;

	/* set necessary data*/
	ri.task = urinst->task;
	ri.sp = (kprobe_opcode_t *)urinst->sp;
	ri.ret_addr = (kprobe_opcode_t *)urinst->ret_addr;

	arch_disarm_urp_inst(&ri, task, tramp);
}

void urinst_info_get_current_hlist(struct hlist_head *head, bool recycle)
{
	unsigned long flags;
	struct task_struct *task = current;
	struct uretprobe_instance *ri;
	struct hlist_head *hhead;
	struct hlist_node *n;
	struct hlist_node *last = NULL;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	spin_lock_irqsave(&uretprobe_lock, flags);
	hhead = uretprobe_inst_table_head(task->mm);
	swap_hlist_for_each_entry_safe(ri, node, n, hhead, hlist) {
		if (task == ri->task) {
			struct urinst_info *urinst;

			urinst = urinst_info_create(ri);
			if (urinst) {
				if (last)
					hlist_add_after(last, &urinst->hlist);
				else
					hlist_add_head(&urinst->hlist, head);

				last = &urinst->hlist;
			}

			if (recycle)
				recycle_urp_inst(ri);
		}
	}
	spin_unlock_irqrestore(&uretprobe_lock, flags);
}
EXPORT_SYMBOL_GPL(urinst_info_get_current_hlist);

void urinst_info_put_current_hlist(struct hlist_head *head,
				  struct task_struct *task)
{
	struct urinst_info *urinst;
	struct hlist_node *tmp;
	DECLARE_NODE_PTR_FOR_HLIST(node);

	swap_hlist_for_each_entry_safe(urinst, node, tmp, head, hlist) {
		/* check on disarm */
		if (task)
			urinst_info_disarm(urinst, task);

		hlist_del(&urinst->hlist);
		urinst_info_destroy(urinst);
	}
}
EXPORT_SYMBOL_GPL(urinst_info_put_current_hlist);


static int once(void)
{
	init_uprobe_table();
	init_uprobes_insn_slots();
	init_uretprobe_inst_table();

	return 0;
}

SWAP_LIGHT_INIT_MODULE(once, swap_arch_init_uprobes, swap_arch_exit_uprobes,
		       NULL, NULL);

MODULE_LICENSE("GPL");
