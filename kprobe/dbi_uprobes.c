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


#include "dbi_uprobes.h"
#include "dbi_insn_slots.h"
#include "dbi_kdebug.h"

#include <linux/hash.h>
#include <linux/mempolicy.h>
#include <linux/module.h>

struct hlist_head uprobe_insn_slot_table[KPROBE_TABLE_SIZE];


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
	for (i = 0; i < KPROBE_TABLE_SIZE; ++i) {
		head = &uprobe_insn_slot_table[i];
		hlist_for_each_entry_rcu (p, node, head, is_hlist_arm) {
			printk("####### find U tgid=%u, addr=%x\n",
					p->tgid, p->addr);
		}
	}
}
#endif


static void add_uprobe_table(struct kprobe *p)
{
#ifdef CONFIG_ARM
	INIT_HLIST_NODE(&p->is_hlist_arm);
	hlist_add_head_rcu(&p->is_hlist_arm, &uprobe_insn_slot_table[hash_ptr (p->ainsn.insn_arm, KPROBE_HASH_BITS)]);
	INIT_HLIST_NODE(&p->is_hlist_thumb);
	hlist_add_head_rcu(&p->is_hlist_thumb, &uprobe_insn_slot_table[hash_ptr (p->ainsn.insn_thumb, KPROBE_HASH_BITS)]);
#else /* CONFIG_ARM */
	INIT_HLIST_NODE(&p->is_hlist);
	hlist_add_head_rcu(&p->is_hlist, &uprobe_insn_slot_table[hash_ptr (p->ainsn.insn, KPROBE_HASH_BITS)]);
#endif /* CONFIG_ARM */
}


static int __register_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
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
	old_p = get_kprobe(p->addr, p->tgid);
	if (old_p) {
#ifdef CONFIG_ARM
		p->safe_arm = old_p->safe_arm;
		p->safe_thumb = old_p->safe_thumb;
#endif
		ret = register_aggr_kprobe(old_p, p);
		if (!ret) {
			atomic_inc(&kprobe_count);
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
	hlist_add_head_rcu(&p->hlist, &kprobe_table[hash_ptr (p->addr, KPROBE_HASH_BITS)]);
	add_uprobe_table(p);
	arch_arm_uprobe(p, task);

out:
	DBPRINTF("out ret = 0x%x\n", ret);
	return ret;
}

void unregister_uprobe(struct kprobe *p, struct task_struct *task, int atomic)
{
	dbi_unregister_kprobe (p, task);
}


int dbi_register_ujprobe(struct task_struct *task, struct jprobe *jp, int atomic)
{
	int ret = 0;

	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_pre_handler;
	jp->kp.break_handler = longjmp_break_handler;

	ret = __register_uprobe(&jp->kp, task, atomic);

	return ret;
}

void dbi_unregister_ujprobe(struct task_struct *task, struct jprobe *jp, int atomic)
{
	unregister_uprobe(&jp->kp, task, atomic);
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

int dbi_register_uretprobe(struct task_struct *task, struct kretprobe *rp, int atomic)
{
	int i, ret = 0;
	struct kretprobe_instance *inst;

	DBPRINTF ("START\n");

	rp->kp.pre_handler = pre_handler_kretprobe;
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
			free_rp_inst (rp);
			ret = -ENOMEM;
			goto out;
		}

		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	rp->nmissed = 0;

	/* Establish function exit probe point */
	ret = arch_prepare_uretprobe(rp, task);
	if (ret) {
		goto out;
	}

	/* Establish function entry probe point */
	ret = __register_uprobe(&rp->kp, task, atomic);
	if (ret) {
		free_rp_inst(rp);
		goto out;
	}

	arch_arm_uretprobe(rp, task);
out:
	return ret;
}

int dbi_disarm_urp_inst(struct kretprobe_instance *ri, struct task_struct *rm_task)
{
	struct task_struct *task = rm_task ? rm_task : ri->task;
	kprobe_opcode_t *tramp = (kprobe_opcode_t *)(ri->rp->kp.ainsn.insn +
			UPROBES_TRAMP_RET_BREAK_IDX);
	kprobe_opcode_t *stack = ri->sp - RETPROBE_STACK_DEPTH;
	kprobe_opcode_t *found = NULL;
	kprobe_opcode_t *buf[RETPROBE_STACK_DEPTH];
	int i, retval;

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
				(unsigned long)found, (unsigned long)ri->sp,
				found - ri->sp, ri->rp->kp.addr);
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
					(unsigned long)ri->sp, ra, ri->rp->kp.addr);
			retval = -ENOENT;
		}
	}

out:
	return retval;
}

void dbi_unregister_uretprobe(struct task_struct *task, struct kretprobe *rp, int atomic, int not_rp2)
{
	unsigned long flags;
	struct kretprobe_instance *ri;
	struct kretprobe *rp2 = NULL;

	spin_lock_irqsave (&kretprobe_lock, flags);

	while ((ri = get_used_rp_inst(rp)) != NULL) {
		if (dbi_disarm_urp_inst(ri, NULL) != 0)
			/*panic*/printk("%s (%d/%d): cannot disarm urp instance (%08lx)\n",
					ri->task->comm, ri->task->tgid, ri->task->pid,
					(unsigned long)rp->kp.addr);
		recycle_rp_inst(ri);
	}

	if (hlist_empty(&rp->used_instances) || not_rp2) {
		struct kprobe *p = &rp->kp;
		// if there are no used retprobe instances (i.e. function is not entered) - disarm retprobe
		arch_disarm_uretprobe(rp, task);//vmas[1], pages[1], kaddrs[1]);
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
			arch_disarm_uprobe(&rp->kp, task);
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

	while ((ri = get_used_rp_inst(rp)) != NULL) {
		ri->rp = NULL;
		ri->rp2 = rp2;
		hlist_del(&ri->uflist);
	}

	spin_unlock_irqrestore(&kretprobe_lock, flags);
	free_rp_inst(rp);

	unregister_uprobe(&rp->kp, task, atomic);
}

void dbi_unregister_all_uprobes(struct task_struct *task, int atomic)
{
	struct hlist_head *head;
	struct hlist_node *node, *tnode;
	struct kprobe *p;
	int i;

	for (i = 0; i < KPROBE_TABLE_SIZE; ++i) {
		head = &kprobe_table[i];
		hlist_for_each_entry_safe(p, node, tnode, head, hlist) {
			if (p->tgid == task->tgid) {
				printk("dbi_unregister_all_uprobes: delete uprobe at %p[%lx] for %s/%d\n",
						p->addr, (unsigned long)p->opcode, task->comm, task->pid);
				unregister_uprobe(p, task, atomic);
			}
		}
	}
}

void init_uprobes_insn_slots(int i)
{
	INIT_HLIST_HEAD(&uprobe_insn_slot_table[i]);
}

void dbi_uprobe_return(void)
{
	dbi_arch_uprobe_return();
}


EXPORT_SYMBOL_GPL(dbi_uprobe_return);
EXPORT_SYMBOL_GPL(dbi_register_ujprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_ujprobe);
EXPORT_SYMBOL_GPL(dbi_register_uretprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_uretprobe);
EXPORT_SYMBOL_GPL(dbi_unregister_all_uprobes);
