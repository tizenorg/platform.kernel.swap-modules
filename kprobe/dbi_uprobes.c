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


extern atomic_t kprobe_count;
extern struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];
extern struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];
extern spinlock_t kretprobe_lock;

extern struct kretprobe *sched_rp;

struct hlist_head uprobe_insn_slot_table[KPROBE_TABLE_SIZE];

static 
int __register_uprobe (struct kprobe *p, struct task_struct *task, int atomic, unsigned long called_from)
{
	int ret = 0;
	struct kprobe *old_p;

//	printk (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> %s %d\n", __FUNCTION__, __LINE__);

	if (!p->addr)
		return -EINVAL;

	DBPRINTF ("p->addr = 0x%p p = 0x%p\n", p->addr, p);

// thumb address = address-1;
#if defined(CONFIG_ARM)
	if ((unsigned long) p->addr & 0x01)
	{
		p->addr = (unsigned long)p->addr & 0xfffffffe;
	}
#endif

	p->mod_refcounted = 0;
	p->nmissed = 0;
#ifdef KPROBES_PROFILE
	p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
	p->hnd_tm_sum.tv_sec = p->hnd_tm_sum.tv_usec = 0;
	p->count = 0;
#endif

	// get the first item
	old_p = get_kprobe (p->addr, p->tgid, NULL);
	if (old_p)
	{
		ret = register_aggr_kprobe (old_p, p);
		if (!ret)
			atomic_inc (&kprobe_count);
		DBPRINTF ("goto out\n", ret);
		goto out;
	}

//	printk ("================================ %s %d\n", __FUNCTION__, __LINE__);
	if ((ret = arch_prepare_uprobe (p, task, atomic)) != 0)
	{
//		printk ("================================ %s %d\n", __FUNCTION__, __LINE__);
       	DBPRINTF ("goto out\n", ret);
		goto out;
	}

//	printk ("================================ %s %d\n", __FUNCTION__, __LINE__);
	DBPRINTF ("before out ret = 0x%x\n", ret);

	INIT_HLIST_NODE (&p->hlist);
//	printk ("================================ %s %d\n", __FUNCTION__, __LINE__);
	hlist_add_head_rcu (&p->hlist, &kprobe_table[hash_ptr (p->addr, KPROBE_HASH_BITS)]);

	INIT_HLIST_NODE (&p->is_hlist);
//	printk ("================================ %s %d\n", __FUNCTION__, __LINE__);
	hlist_add_head_rcu (&p->is_hlist, &uprobe_insn_slot_table[hash_ptr (p->ainsn.insn, KPROBE_HASH_BITS)]);

//	printk ("================================ %s %d\n", __FUNCTION__, __LINE__);
	arch_arm_uprobe (p, task);
//	printk ("================================ %s %d\n", __FUNCTION__, __LINE__);

out:
	DBPRINTF ("out ret = 0x%x\n", ret);

//	printk ("<<<<<<<<<<<<<<<<<<<<<<<<<<<<< %s %d\n", __FUNCTION__, __LINE__);
	return ret;
}

void unregister_uprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	unregister_kprobe (p, task, atomic);
}


int register_ujprobe (struct task_struct *task, struct mm_struct *mm, struct jprobe *jp, int atomic)
{
	int ret = 0;

	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_pre_handler;
	jp->kp.break_handler = longjmp_break_handler;

	ret = __register_uprobe (&jp->kp, task, atomic,
			(unsigned long) __builtin_return_address (0));

	return ret;
}

void unregister_ujprobe (struct task_struct *task, struct jprobe *jp, int atomic)
{
	unregister_uprobe (&jp->kp, task, atomic);
}

int register_uretprobe (struct task_struct *task, struct mm_struct *mm, struct kretprobe *rp, int atomic)
{
	int ret = 0;
	struct kretprobe_instance *inst;
	int i;

	DBPRINTF ("START\n");

	rp->kp.pre_handler = pre_handler_kretprobe;
	rp->kp.post_handler = NULL;
	rp->kp.fault_handler = NULL;
	rp->kp.break_handler = NULL;

	rp->disarm = 0;

	/* Pre-allocate memory for max kretprobe instances */
	if (rp->maxactive <= 0)
	{
#if 1//def CONFIG_PREEMPT
		rp->maxactive = max (10, 2 * NR_CPUS);
#else
		rp->maxactive = NR_CPUS;
#endif
	}
	INIT_HLIST_HEAD (&rp->used_instances);
	INIT_HLIST_HEAD (&rp->free_instances);
	for (i = 0; i < rp->maxactive; i++)
	{
		inst = kmalloc (sizeof (struct kretprobe_instance), GFP_KERNEL);
		if (inst == NULL)
		{
			free_rp_inst (rp);
			ret = -ENOMEM;
			goto out;
		}
		INIT_HLIST_NODE (&inst->uflist);
		hlist_add_head (&inst->uflist, &rp->free_instances);
	}

	rp->nmissed = 0;

	/* Establish function exit probe point */
	if ((ret = arch_prepare_uretprobe (rp, task)) != 0)
		goto out;
	/* Establish function entry probe point */
	if ((ret = __register_uprobe (&rp->kp, task, atomic,
					(unsigned long) __builtin_return_address (0))) != 0)
	{
		free_rp_inst (rp);
		goto out;
	}

	arch_arm_uretprobe (rp, task);//vmas[1], pages[1], kaddrs[1]);
out:
	return ret;
}


void unregister_uretprobe (struct task_struct *task, struct kretprobe *rp, int atomic)
{
	unsigned long flags;
	struct kretprobe_instance *ri;
	struct kretprobe *rp2 = NULL;

	spin_lock_irqsave (&kretprobe_lock, flags);
	if (hlist_empty (&rp->used_instances))
	{
		// if there are no used retprobe instances (i.e. function is not entered) - disarm retprobe
		arch_disarm_uretprobe (rp, task);//vmas[1], pages[1], kaddrs[1]);
	}
	else
	{
		rp2 = clone_kretprobe (rp);
		if (!rp2)
			DBPRINTF ("unregister_uretprobe addr %p: failed to clone retprobe!", rp->kp.addr);
		else
		{
			DBPRINTF ("initiating deferred retprobe deletion addr %p", rp->kp.addr);
			printk ("initiating deferred retprobe deletion addr %p\n", rp->kp.addr);
			rp2->disarm = 1;
		}
	}

	while ((ri = get_used_rp_inst (rp)) != NULL)
	{
		ri->rp = NULL;
		ri->rp2 = rp2;
		hlist_del (&ri->uflist);
	}
	spin_unlock_irqrestore (&kretprobe_lock, flags);
	free_rp_inst (rp);

	unregister_uprobe (&rp->kp, task, atomic);
}

void unregister_all_uprobes (struct task_struct *task, int atomic)
{
	struct hlist_head *head;
	struct hlist_node *node, *tnode;
	struct kprobe *p;
	int i;

	for(i = 0; i < KPROBE_TABLE_SIZE; i++){
		head = &kprobe_table[i];
		hlist_for_each_entry_safe (p, node, tnode, head, hlist){			
			if(p->tgid == task->tgid){
				printk("unregister_all_uprobes: delete uprobe at %pf for %s/%d\n", p->addr, task->comm, task->pid);
				unregister_uprobe (p, task, atomic);
			}
		}
	}
	purge_garbage_uslots(task, atomic);

#if defined(CONFIG_ARM)
	arch_arm_reinit();
#endif
}

void init_uprobes_insn_slots(int i) 
{
	INIT_HLIST_HEAD (&uprobe_insn_slot_table[i]);
}

void uprobe_return (void)
{
	arch_uprobe_return();
}


EXPORT_SYMBOL_GPL (uprobe_return);
EXPORT_SYMBOL_GPL (register_ujprobe);
EXPORT_SYMBOL_GPL (unregister_ujprobe);
EXPORT_SYMBOL_GPL (register_uretprobe);
EXPORT_SYMBOL_GPL (unregister_uretprobe);
EXPORT_SYMBOL_GPL (unregister_all_uprobes);

