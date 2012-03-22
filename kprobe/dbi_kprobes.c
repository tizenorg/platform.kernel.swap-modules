// src_kprobes.c

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
#include "dbi_uprobes.h"


#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif

#include <linux/hash.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>



extern unsigned int *sched_addr;
extern unsigned int *fork_addr;

extern struct hlist_head kprobe_insn_pages;

extern unsigned long (*kallsyms_search) (const char *name);

DEFINE_PER_CPU (struct kprobe *, current_kprobe) = NULL;
DEFINE_PER_CPU (struct kprobe_ctlblk, kprobe_ctlblk);

DEFINE_SPINLOCK (kretprobe_lock);	/* Protects kretprobe_inst_table */
DEFINE_PER_CPU (struct kprobe *, kprobe_instance) = NULL;

struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];
struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];

atomic_t kprobe_count;


void kretprobe_assert (struct kretprobe_instance *ri, unsigned long orig_ret_address, unsigned long trampoline_address)
{
	if (!orig_ret_address || (orig_ret_address == trampoline_address))
		panic ("kretprobe BUG!: Processing kretprobe %p @ %p\n", ri->rp, ri->rp->kp.addr);
}


/* We have preemption disabled.. so it is safe to use __ versions */
static inline 
void set_kprobe_instance (struct kprobe *kp)
{
	__get_cpu_var (kprobe_instance) = kp;
}

static inline 
void reset_kprobe_instance (void)
{
	__get_cpu_var (kprobe_instance) = NULL;
}

/* kprobe_running() will just return the current_kprobe on this CPU */
struct kprobe *kprobe_running (void)
{
	return (__get_cpu_var (current_kprobe));
}

void reset_current_kprobe (void)
{
	__get_cpu_var (current_kprobe) = NULL;
}

struct kprobe_ctlblk *get_kprobe_ctlblk (void)
{
	return (&__get_cpu_var (kprobe_ctlblk));
}

/*
 * This routine is called either:
 * 	- under the kprobe_mutex - during kprobe_[un]register()
 * 				OR
 * 	- with preemption disabled - from arch/xxx/kernel/kprobes.c
 */
struct kprobe *get_kprobe (void *addr, int tgid, struct task_struct *ctask)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *retVal = NULL;
	int ret = 0, uprobe_found;
	struct page *page = 0, *tpage = 0;
	struct vm_area_struct *vma = 0;
	struct task_struct *task = 0;
	void *paddr = 0;


	if (ctask && ctask->active_mm)
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
		ret = get_user_pages(ctask, ctask->active_mm,
				     (unsigned long)addr, 1, 0, 0,
				     &tpage, NULL);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
		ret = get_user_pages_uprobe(ctask, ctask->active_mm,
					    (unsigned long)addr, 1, 0, 0,
					    &tpage, NULL);
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
		if (ret <= 0)
			DBPRINTF ("get_user_pages for task %d at %p failed!", current->pid, addr);
		else
		{
			paddr = page_address (tpage);
			page_cache_release (tpage);
		}
	}

	//TODO: test - two processes invokes instrumented function
	head = &kprobe_table[hash_ptr (addr, KPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu (p, node, head, hlist)
	{
		//if looking for kernel probe and this is kernel probe with the same addr OR
		//if looking for the user space probe and this is user space probe probe with the same addr and pid
		DBPRINTF ("get_kprobe: check probe at %p/%p, task %d/%d", addr, p->addr, tgid, p->tgid);
		if (p->addr == addr)
		{
			uprobe_found = 0;
			if (tgid == p->tgid)
				uprobe_found = 1;
			if (!tgid || uprobe_found)
			{
				retVal = p;
				if (tgid)
					DBPRINTF ("get_kprobe: found user space probe at %p for task %d", p->addr, p->tgid);
				else
					DBPRINTF ("get_kprobe: found kernel probe at %p", p->addr);
				break;
			}
		}
		else if (tgid != p->tgid)
		{
			// if looking for the user space probe and this is user space probe 
			// with another addr and pid but with the same offset whithin the page
			// it could be that it is the same probe (with address from other user space)
			// we should handle it as usual probe but without notification to user 
			if (paddr && tgid && (((unsigned long) addr & ~PAGE_MASK) == ((unsigned long) p->addr & ~PAGE_MASK))
					&& p->tgid)
			{
				DBPRINTF ("get_kprobe: found user space probe at %p in task %d. possibly for addr %p in task %d", p->addr, p->tgid, addr, tgid);
				// this probe has the same offset in the page
				// look in the probes for the other pids                                
				// get page for user space probe addr
				rcu_read_lock ();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
				task = find_task_by_pid (p->tgid);
#else //lif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
				task = pid_task(find_pid_ns(p->tgid, &init_pid_ns), PIDTYPE_PID);
#endif
				if (task)
					get_task_struct (task);
				rcu_read_unlock ();
				if (!task)
				{
					DBPRINTF ("task for pid %d not found! Dead probe?", p->tgid);
					continue;
				}
				if (task->active_mm)
				{
					if (page_present (task->active_mm, (unsigned long) p->addr))
					{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
						ret = get_user_pages(task,
								     task->active_mm,
								     (unsigned long)p->addr,
								     1, 0, 0, &page, &vma);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
						ret = get_user_pages_uprobe(task,
									    task->active_mm,
									    (unsigned long)p->addr,
									    1, 0, 0, &page, &vma);
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
						if (ret <= 0)
							DBPRINTF ("get_user_pages for task %d at %p failed!", p->tgid, p->addr);
					}
					else
						ret = -1;
				}
				else
				{
					DBPRINTF ("task %d has no mm!", task->pid);
					ret = -1;
				}
				//put_task_struct (task);

				if (ret <= 0)
					continue;
				if (paddr == page_address (page))
				{
					retVal = p;	// we found the probe in other process address space
					DBPRINTF ("get_kprobe: found user space probe at %p in task %d for addr %p in task %d", p->addr, p->tgid, addr, tgid);
					panic ("user space probe from another process");
				}
				page_cache_release (page);
				if (retVal)
					break;
			}
		}
	}

	DBPRINTF ("get_kprobe: probe %p", retVal);
	return retVal;
}


/*
 * Aggregate handlers for multiple kprobes support - these handlers
 * take care of invoking the individual kprobe handlers on p->list
 */
static 
int aggr_pre_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *kp;
	int ret;

	list_for_each_entry_rcu (kp, &p->list, list)
	{
		if (kp->pre_handler)
		{
			set_kprobe_instance (kp);
			ret = kp->pre_handler (kp, regs);
			if (ret)
				return ret;
		}
		reset_kprobe_instance ();
	}
	return 0;
}

static 
void aggr_post_handler (struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	struct kprobe *kp;

	list_for_each_entry_rcu (kp, &p->list, list)
	{
		if (kp->post_handler)
		{
			set_kprobe_instance (kp);
			kp->post_handler (kp, regs, flags);
			reset_kprobe_instance ();
		}
	}
	return;
}

static 
int aggr_fault_handler (struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	struct kprobe *cur = __get_cpu_var (kprobe_instance);

	/*
	 * if we faulted "during" the execution of a user specified
	 * probe handler, invoke just that probe's fault handler
	 */
	if (cur && cur->fault_handler)
	{
		if (cur->fault_handler (cur, regs, trapnr))
			return 1;
	}
	return 0;
}

static 
int aggr_break_handler (struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *cur = __get_cpu_var (kprobe_instance);
	int ret = 0;
	DBPRINTF ("cur = 0x%p\n", cur);
	if (cur)
		DBPRINTF ("cur = 0x%p cur->break_handler = 0x%p\n", cur, cur->break_handler);

	if (cur && cur->break_handler)
	{
		if (cur->break_handler (cur, regs /*, vma, page, kaddr */ ))
			ret = 1;
	}
	reset_kprobe_instance ();
	return ret;
}

/* Walks the list and increments nmissed count for multiprobe case */
void kprobes_inc_nmissed_count (struct kprobe *p)
{
	struct kprobe *kp;
	if (p->pre_handler != aggr_pre_handler)
	{
		p->nmissed++;
	}
	else
	{
		list_for_each_entry_rcu (kp, &p->list, list) kp->nmissed++;
	}
	return;
}

/* Called with kretprobe_lock held */
struct kretprobe_instance *get_free_rp_inst (struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;
	hlist_for_each_entry (ri, node, &rp->free_instances, uflist)
		return ri;
	if(!alloc_nodes_kretprobe(rp)){
	     hlist_for_each_entry (ri, node, &rp->free_instances, uflist)
		  return ri;
	}
	return NULL;
}

/* Called with kretprobe_lock held */
struct kretprobe_instance *get_free_rp_inst_no_alloc (struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;
	hlist_for_each_entry (ri, node, &rp->free_instances, uflist)
		return ri;
	return NULL;
}

/* Called with kretprobe_lock held */
struct kretprobe_instance *get_used_rp_inst (struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;
	hlist_for_each_entry (ri, node, &rp->used_instances, uflist) return ri;
	return NULL;
}

/* Called with kretprobe_lock held */
void add_rp_inst (struct kretprobe_instance *ri)
{
	/*
	 * Remove rp inst off the free list -
	 * Add it back when probed function returns
	 */
	hlist_del (&ri->uflist);

	/* Add rp inst onto table */
	INIT_HLIST_NODE (&ri->hlist);
	/*
	 * We are using different hash keys (task and mm) for finding kernel
	 * space and user space probes.  Kernel space probes can change mm field in
	 * task_struct.  User space probes can be shared between threads of one
	 * process so they have different task but same mm.
	 */
	if (ri->rp->kp.tgid) {
		hlist_add_head (&ri->hlist, &kretprobe_inst_table[hash_ptr (ri->task->mm, KPROBE_HASH_BITS)]);
	} else {
		hlist_add_head (&ri->hlist, &kretprobe_inst_table[hash_ptr (ri->task, KPROBE_HASH_BITS)]);
	}

	/* Also add this rp inst to the used list. */
	INIT_HLIST_NODE (&ri->uflist);
	hlist_add_head (&ri->uflist, &ri->rp->used_instances);
}

/* Called with kretprobe_lock held */
void recycle_rp_inst (struct kretprobe_instance *ri, struct hlist_head *head)
{
	if (ri->rp)
	{
		hlist_del (&ri->hlist);
		/* remove rp inst off the used list */
		hlist_del (&ri->uflist);
		/* put rp inst back onto the free list */
		INIT_HLIST_NODE (&ri->uflist);
		hlist_add_head (&ri->uflist, &ri->rp->free_instances);
	} else if (!ri->rp2) {
		/*
		 * This is __switch_to retprobe instance.  It has neither rp nor rp2.
		 */
		hlist_del (&ri->hlist);
	}
}

struct hlist_head  * kretprobe_inst_table_head (void *hash_key)
{
	return &kretprobe_inst_table[hash_ptr (hash_key, KPROBE_HASH_BITS)];
}

void free_rp_inst (struct kretprobe *rp)
{
	struct kretprobe_instance *ri;
	while ((ri = get_free_rp_inst_no_alloc (rp)) != NULL)
	{
		hlist_del (&ri->uflist);
		kfree (ri);
	}
}

/*
 * Keep all fields in the kprobe consistent
 */
static inline 
void copy_kprobe (struct kprobe *old_p, struct kprobe *p)
{
	memcpy (&p->opcode, &old_p->opcode, sizeof (kprobe_opcode_t));
	memcpy (&p->ainsn, &old_p->ainsn, sizeof (struct arch_specific_insn));
	p->tgid = old_p->tgid;
	p->ss_addr = old_p->ss_addr;
	//p->spid = old_p->spid;
}

/*
 * Add the new probe to old_p->list. Fail if this is the
 * second jprobe at the address - two jprobes can't coexist
 */
int add_new_kprobe (struct kprobe *old_p, struct kprobe *p)
{
	if (p->break_handler)
	{
		if (old_p->break_handler)
			return -EEXIST;
		list_add_tail_rcu (&p->list, &old_p->list);
		old_p->break_handler = aggr_break_handler;
	}
	else
		list_add_rcu (&p->list, &old_p->list);
	if (p->post_handler && !old_p->post_handler)
		old_p->post_handler = aggr_post_handler;
	return 0;
}

/**
 * hlist_replace_rcu - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * The @old entry will be replaced with the @new entry atomically.
 */
inline void dbi_hlist_replace_rcu (struct hlist_node *old, struct hlist_node *new)
{
	struct hlist_node *next = old->next;

	new->next = next;
	new->pprev = old->pprev;
	smp_wmb ();
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
static inline 
void add_aggr_kprobe (struct kprobe *ap, struct kprobe *p)
{
	copy_kprobe (p, ap);
	//flush_insn_slot (ap);
	ap->addr = p->addr;
	ap->pre_handler = aggr_pre_handler;
	ap->fault_handler = aggr_fault_handler;
	if (p->post_handler)
		ap->post_handler = aggr_post_handler;
	if (p->break_handler)
		ap->break_handler = aggr_break_handler;

	INIT_LIST_HEAD (&ap->list);
	list_add_rcu (&p->list, &ap->list);

	dbi_hlist_replace_rcu (&p->hlist, &ap->hlist);
}

/*
 * This is the second or subsequent kprobe at the address - handle
 * the intricacies
 */
int register_aggr_kprobe (struct kprobe *old_p, struct kprobe *p)
{
	int ret = 0;
	struct kprobe *ap;
	DBPRINTF ("start\n");

	DBPRINTF ("p = %p old_p = %p \n", p, old_p);
	if (old_p->pre_handler == aggr_pre_handler)
	{
		DBPRINTF ("aggr_pre_handler \n");

		copy_kprobe (old_p, p);
		ret = add_new_kprobe (old_p, p);
	}
	else
	{
		DBPRINTF ("kzalloc\n");

#ifdef kzalloc
		ap = kzalloc (sizeof (struct kprobe), GFP_KERNEL);
#else
		ap = kmalloc (sizeof (struct kprobe), GFP_KERNEL);
		if (ap)
			memset (ap, 0, sizeof (struct kprobe));
#endif
		if (!ap)
			return -ENOMEM;
		add_aggr_kprobe (ap, old_p);
		copy_kprobe (ap, p);
		DBPRINTF ("ap = %p p = %p old_p = %p \n", ap, p, old_p);
		ret = add_new_kprobe (ap, p);
	}
	return ret;
}

static 
int __dbi_register_kprobe (struct kprobe *p, unsigned long called_from, int atomic)
{
	struct kprobe *old_p;
	//      struct module *probed_mod;
	int ret = 0;
	/*
	 * If we have a symbol_name argument look it up,
	 * and add it to the address.  That way the addr
	 * field can either be global or relative to a symbol.
	 */
	if (p->symbol_name)
	{
		if (p->addr)
			return -EINVAL;
		p->addr = (unsigned int) kallsyms_search (p->symbol_name);
	}

	if (!p->addr)
		return -EINVAL;
	DBPRINTF ("p->addr = 0x%p\n", p->addr);
	p->addr = (kprobe_opcode_t *) (((char *) p->addr) + p->offset);
	DBPRINTF ("p->addr = 0x%p p = 0x%p\n", p->addr, p);

	/*	if ((!kernel_text_address((unsigned long) p->addr)) ||
		in_kprobes_functions((unsigned long) p->addr))
		return -EINVAL;*/

#ifdef KPROBES_PROFILE
	p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
	p->hnd_tm_sum.tv_sec = p->hnd_tm_sum.tv_usec = 0;
	p->count = 0;
#endif
	p->mod_refcounted = 0;
	//p->proc_prio = 0;
	//p->proc_sched = 0;    
	//p->spid = -1;
	//p->irq = 0;
	//p->task_flags = 0;
	/*
	// Check are we probing a module
	if ((probed_mod = module_text_address((unsigned long) p->addr))) {
	struct module *calling_mod = module_text_address(called_from);
	// We must allow modules to probe themself and
	// in this case avoid incrementing the module refcount,
	// so as to allow unloading of self probing modules.
	//
	if (calling_mod && (calling_mod != probed_mod)) {
	if (unlikely(!try_module_get(probed_mod)))
	return -EINVAL;
	p->mod_refcounted = 1;
	} else
	probed_mod = NULL;
	}
	 */
	p->nmissed = 0;
	//      mutex_lock(&kprobe_mutex);
	old_p = get_kprobe (p->addr, 0, NULL);
	if (old_p)
	{
		ret = register_aggr_kprobe (old_p, p);
		if (!ret)
			atomic_inc (&kprobe_count);
		goto out;
	}

	if ((ret = arch_prepare_kprobe (p)) != 0)
		goto out;

	DBPRINTF ("before out ret = 0x%x\n", ret);

	INIT_HLIST_NODE (&p->hlist);
	hlist_add_head_rcu (&p->hlist, &kprobe_table[hash_ptr (p->addr, KPROBE_HASH_BITS)]);

	/*	if (atomic_add_return(1, &kprobe_count) == \
		(ARCH_INACTIVE_KPROBE_COUNT + 1))
		register_page_fault_notifier(&kprobe_page_fault_nb);*/

	arch_arm_kprobe (p);

out:
	//      mutex_unlock(&kprobe_mutex);
	/*
	   if (ret && probed_mod)
	   module_put(probed_mod);
	 */
	DBPRINTF ("out ret = 0x%x\n", ret);

	return ret;
}


int dbi_register_kprobe (struct kprobe *p, int atomic)
{
	return __dbi_register_kprobe (p, (unsigned long) __builtin_return_address (0), atomic);
}

void dbi_unregister_kprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	//      struct module *mod;
	struct kprobe *old_p, *list_p;
	int cleanup_p, pid = 0;

	//      mutex_lock(&kprobe_mutex);

	pid = p->tgid;

	old_p = get_kprobe (p->addr, pid, NULL);
	DBPRINTF ("dbi_unregister_kprobe p=%p old_p=%p", p, old_p);
	if (unlikely (!old_p))
	{
		//              mutex_unlock(&kprobe_mutex);
		return;
	}
	if (p != old_p)
	{
		list_for_each_entry_rcu (list_p, &old_p->list, list) 
			if (list_p == p)
				/* kprobe p is a valid probe */
				goto valid_p;
		//              mutex_unlock(&kprobe_mutex);
		return;
	}
valid_p:
	DBPRINTF ("dbi_unregister_kprobe valid_p");
	if ((old_p == p) || ((old_p->pre_handler == aggr_pre_handler) && 
				(p->list.next == &old_p->list) && (p->list.prev == &old_p->list)))
	{
		/* Only probe on the hash list */
		DBPRINTF ("dbi_unregister_kprobe disarm pid=%d", pid);
		if (pid)
			arch_disarm_uprobe (p, task);//vma, page, kaddr);
		else
			arch_disarm_kprobe (p);
		hlist_del_rcu (&old_p->hlist);
		cleanup_p = 1;
	}
	else
	{
		list_del_rcu (&p->list);
		cleanup_p = 0;
	}
	DBPRINTF ("dbi_unregister_kprobe cleanup_p=%d", cleanup_p);
	//      mutex_unlock(&kprobe_mutex);

	//      synchronize_sched();
	/*
	   if (p->mod_refcounted &&
	   (mod = module_text_address((unsigned long)p->addr)))
	   module_put(mod);
	 */
	if (cleanup_p)
	{
		if (p != old_p)
		{
			list_del_rcu (&p->list);
			kfree (old_p);
		}
		arch_remove_kprobe (p, task);
	}
	else
	{
		///             mutex_lock(&kprobe_mutex);
		if (p->break_handler)
			old_p->break_handler = NULL;
		if (p->post_handler)
		{
			list_for_each_entry_rcu (list_p, &old_p->list, list)
			{
				if (list_p->post_handler)
				{
					cleanup_p = 2;
					break;
				}
			}
			if (cleanup_p == 0)
				old_p->post_handler = NULL;
		}
		//              mutex_unlock(&kprobe_mutex);
	}

	/* Call unregister_page_fault_notifier()
	 * if no probes are active
	 */
	//      mutex_lock(&kprobe_mutex);
	/*	if (atomic_add_return(-1, &kprobe_count) == \
		ARCH_INACTIVE_KPROBE_COUNT)
		unregister_page_fault_notifier(&kprobe_page_fault_nb);*/
	//      mutex_unlock(&kprobe_mutex);
	return;
}

int dbi_register_jprobe (struct jprobe *jp, int atomic)
{
	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_pre_handler;
	jp->kp.break_handler = longjmp_break_handler;

	return __dbi_register_kprobe (&jp->kp, (unsigned long) __builtin_return_address (0), atomic);
}

void dbi_unregister_jprobe (struct jprobe *jp, int atomic)
{
	dbi_unregister_kprobe (&jp->kp, 0, atomic);
}

/*
 * This kprobe pre_handler is registered with every kretprobe. When probe
 * hits it will set up the return probe.
 */
int pre_handler_kretprobe (struct kprobe *p, struct pt_regs *regs)
{
	struct kretprobe *rp = container_of (p, struct kretprobe, kp);
	unsigned long flags = 0;
	DBPRINTF ("START\n");

	/*TODO: consider to only swap the RA after the last pre_handler fired */
	spin_lock_irqsave (&kretprobe_lock, flags);
	if (!rp->disarm)
		__arch_prepare_kretprobe (rp, regs);
	spin_unlock_irqrestore (&kretprobe_lock, flags);
	DBPRINTF ("END\n");
	return 0;
}

struct kretprobe *sched_rp;

#define SCHED_RP_NR 200
#define COMMON_RP_NR 10

int alloc_nodes_kretprobe(struct kretprobe *rp)
{
     int alloc_nodes;
     struct kretprobe_instance *inst;
     int i;

     DBPRINTF("Alloc aditional mem for retprobes");

     if((unsigned int)rp->kp.addr == sched_addr){
	  rp->maxactive += SCHED_RP_NR;//max (100, 2 * NR_CPUS);
	  alloc_nodes = SCHED_RP_NR;
     }
     else
     {
#if 1//def CONFIG_PREEMPT
	  rp->maxactive += max (COMMON_RP_NR, 2 * NR_CPUS);
#else
	  rp->maxacpptive += NR_CPUS;
#endif
	  alloc_nodes = COMMON_RP_NR;
     }
     /* INIT_HLIST_HEAD (&rp->used_instances); */
     /* INIT_HLIST_HEAD (&rp->free_instances); */
     for (i = 0; i < alloc_nodes; i++)
     {
	  inst = kmalloc (sizeof (struct kretprobe_instance), GFP_ATOMIC);
	  if (inst == NULL)
	  {
	       free_rp_inst (rp);
	       return -ENOMEM;
	  }
	  INIT_HLIST_NODE (&inst->uflist);
	  hlist_add_head (&inst->uflist, &rp->free_instances);
     }

     DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
     return 0;
}

int dbi_register_kretprobe (struct kretprobe *rp, int atomic)
{
	int ret = 0;
	struct kretprobe_instance *inst;
	int i;
	int priority = atomic ? GFP_ATOMIC : GFP_KERNEL;
	DBPRINTF ("START");

	rp->kp.pre_handler = pre_handler_kretprobe;
	rp->kp.post_handler = NULL;
	rp->kp.fault_handler = NULL;
	rp->kp.break_handler = NULL;

	rp->disarm = 0;

	/* Pre-allocate memory for max kretprobe instances */
	if((unsigned int)rp->kp.addr == sched_addr)
		rp->maxactive = SCHED_RP_NR;//max (100, 2 * NR_CPUS);
	else if (rp->maxactive <= 0)
	{
#if 1//def CONFIG_PREEMPT
		rp->maxactive = max (COMMON_RP_NR, 2 * NR_CPUS);
#else
		rp->maxactive = NR_CPUS;
#endif
	}
	INIT_HLIST_HEAD (&rp->used_instances);
	INIT_HLIST_HEAD (&rp->free_instances);
	for (i = 0; i < rp->maxactive; i++)
	{
		inst = kmalloc (sizeof (struct kretprobe_instance), priority);
		if (inst == NULL)
		{
			free_rp_inst (rp);
			return -ENOMEM;
		}
		INIT_HLIST_NODE (&inst->uflist);
		hlist_add_head (&inst->uflist, &rp->free_instances);
	}

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	rp->nmissed = 0;
	/* Establish function entry probe point */
	if ((ret = __dbi_register_kprobe (&rp->kp, (unsigned long) __builtin_return_address (0), atomic)) != 0)
		free_rp_inst (rp);

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	if((unsigned int)rp->kp.addr == sched_addr)
		sched_rp = rp;

	return ret;
}

void dbi_unregister_kretprobe (struct kretprobe *rp, int atomic)
{
	unsigned long flags;
	struct kretprobe_instance *ri;

	dbi_unregister_kprobe (&rp->kp, 0, atomic);

	if((unsigned int)rp->kp.addr == sched_addr)
		sched_rp = NULL;

	/* No race here */
	spin_lock_irqsave (&kretprobe_lock, flags);
	while ((ri = get_used_rp_inst (rp)) != NULL)
	{
		ri->rp = NULL;
		hlist_del (&ri->uflist);
	}
	spin_unlock_irqrestore (&kretprobe_lock, flags);
	free_rp_inst (rp);
}

struct kretprobe * clone_kretprobe (struct kretprobe *rp)
{
	struct kprobe *old_p;
	struct kretprobe *clone = NULL;
	int ret;

	clone = kmalloc (sizeof (struct kretprobe), GFP_KERNEL);
	if (!clone)
	{
		DBPRINTF ("failed to alloc memory for clone probe %p!", rp->kp.addr);
		return NULL;
	}
	memcpy (clone, rp, sizeof (struct kretprobe));
	clone->kp.pre_handler = pre_handler_kretprobe;
	clone->kp.post_handler = NULL;
	clone->kp.fault_handler = NULL;
	clone->kp.break_handler = NULL;
	old_p = get_kprobe (rp->kp.addr, rp->kp.tgid, NULL);
	if (old_p)
	{
		ret = register_aggr_kprobe (old_p, &clone->kp);
		if (ret)
		{
			kfree (clone);
			return NULL;
		}
		atomic_inc (&kprobe_count);
	}

	return clone;
}


int __init init_kprobes (void)
{
	int i, err = 0;

	/* FIXME allocate the probe table, currently defined statically */
	/* initialize all list heads */
	for (i = 0; i < KPROBE_TABLE_SIZE; i++)
	{
		INIT_HLIST_HEAD (&kprobe_table[i]);
		INIT_HLIST_HEAD (&kretprobe_inst_table[i]);

		init_uprobes_insn_slots(i);
	}
	atomic_set (&kprobe_count, 0);

	err = arch_init_kprobes ();

	DBPRINTF ("init_kprobes: arch_init_kprobes - %d", err);

	return err;
}

void __exit exit_kprobes (void)
{
	dbi_arch_exit_kprobes ();
}

module_init (init_kprobes);
module_exit (exit_kprobes);

EXPORT_SYMBOL_GPL (dbi_register_kprobe);
EXPORT_SYMBOL_GPL (dbi_unregister_kprobe);
EXPORT_SYMBOL_GPL (dbi_register_jprobe);
EXPORT_SYMBOL_GPL (dbi_unregister_jprobe);
EXPORT_SYMBOL_GPL (dbi_jprobe_return);
EXPORT_SYMBOL_GPL (dbi_register_kretprobe);
EXPORT_SYMBOL_GPL (dbi_unregister_kretprobe);

MODULE_LICENSE ("Dual BSD/GPL");

