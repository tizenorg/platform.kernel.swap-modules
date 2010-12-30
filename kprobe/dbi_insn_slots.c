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
 *  modules/kprobe/dbi_insn_slots.c
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

#include "dbi_insn_slots.h"
#include "dbi_uprobes.h"
#include "dbi_kdebug.h"

#include <linux/hash.h>
#include <linux/mman.h>
#include <linux/hugetlb.h>

#include <linux/slab.h>



extern struct hlist_head uprobe_insn_slot_table[KPROBE_TABLE_SIZE];

struct hlist_head kprobe_insn_pages;
int kprobe_garbage_slots;
struct hlist_head uprobe_insn_pages;
int uprobe_garbage_slots;


struct kprobe_insn_page
{
	struct hlist_node hlist;
	kprobe_opcode_t *insns;	/* Page of instruction slots */
	char *slot_used;	
	int nused;
	int ngarbage;
	int tgid;
};

enum kprobe_slot_state
{
	SLOT_CLEAN = 0,
	SLOT_DIRTY = 1,
	SLOT_USED = 2,
};


unsigned long alloc_user_pages(struct task_struct *task, unsigned long len, unsigned long prot, unsigned long flags, int atomic)
{
	long ret = 0;
	struct task_struct *otask = current;
	struct mm_struct *mm;

	mm = atomic ? task->active_mm : get_task_mm (task);
	if (mm){
		if(!atomic)
			down_write (&mm->mmap_sem);
		// FIXME: its seems to be bad decision to replace 'current' pointer temporarily 
		current_thread_info()->task = task;
		ret = (unsigned long)do_mmap_pgoff(0, 0, len, prot, flags, 0);
		current_thread_info()->task = otask;
		if(!atomic){
			up_write (&mm->mmap_sem);
			mmput(mm);
		}
	}
	else
		printk ("proc %d has no mm", task->pid);
	return (unsigned long)ret;
}

	int
check_safety (void)
{
	synchronize_sched ();
	return 0;
}


/**
 * get_us_insn_slot() - Find a slot on an executable page for an instruction.
 * We allocate an executable page if there's no room on existing ones.
 */
kprobe_opcode_t *get_insn_slot (struct task_struct *task, int atomic)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos;
	struct hlist_head *page_list = task ? &uprobe_insn_pages : &kprobe_insn_pages;
	unsigned slots_per_page = INSNS_PER_PAGE, slot_size = MAX_INSN_SIZE;

	if(task) {
		slots_per_page = INSNS_PER_PAGE/UPROBES_TRAMP_LEN;
		slot_size = UPROBES_TRAMP_LEN;
	}
	else {
		slots_per_page = INSNS_PER_PAGE/KPROBES_TRAMP_LEN;
		slot_size = KPROBES_TRAMP_LEN;		
	}

retry:
	hlist_for_each_entry (kip, pos, page_list, hlist)
	{
		if (kip->nused < slots_per_page)
		{
			int i;
			for (i = 0; i < slots_per_page; i++)
			{
				if (kip->slot_used[i] == SLOT_CLEAN)
				{
					if(!task || (kip->tgid == task->tgid)){
						kip->slot_used[i] = SLOT_USED;
						kip->nused++;
						return kip->insns + (i * slot_size);
					}
				}
			}
			/* Surprise!  No unused slots.  Fix kip->nused. */
			kip->nused = slots_per_page;
		}
	}

	/* If there are any garbage slots, collect it and try again. */
	if(task) {
		if (uprobe_garbage_slots && collect_garbage_slots(page_list, task) == 0)
			goto retry;
	}
	else {
		if (kprobe_garbage_slots && collect_garbage_slots(page_list, task) == 0)
			goto retry;		
	}

	/* All out of space.  Need to allocate a new page. Use slot 0. */
	kip = kmalloc(sizeof(struct kprobe_insn_page), GFP_KERNEL);
	if (!kip)
		return NULL;

	kip->slot_used = kmalloc(sizeof(char)*slots_per_page, GFP_KERNEL);
	if (!kip->slot_used){
		kfree(kip);
		return NULL;
	}

	if(task) {
		kip->insns = (kprobe_opcode_t *)alloc_user_pages(task, PAGE_SIZE, 
				PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, atomic);
	}
	else {
		kip->insns = kmalloc(PAGE_SIZE, GFP_KERNEL);
	}
	if (!kip->insns)
	{
		kfree (kip->slot_used);
		kfree (kip);
		return NULL;
	}	
	INIT_HLIST_NODE (&kip->hlist);
	hlist_add_head (&kip->hlist, page_list);
	memset(kip->slot_used, SLOT_CLEAN, slots_per_page);
	kip->slot_used[0] = SLOT_USED;
	kip->nused = 1;
	kip->ngarbage = 0;
	kip->tgid = task ? task->tgid : 0;
	return kip->insns;
}

/* Return 1 if all garbages are collected, otherwise 0. */
static 
int collect_one_slot (struct hlist_head *page_list, struct task_struct *task, 
		struct kprobe_insn_page *kip, int idx)
{
	kip->slot_used[idx] = SLOT_CLEAN;
	kip->nused--;
	DBPRINTF("collect_one_slot: nused=%d", kip->nused);
	if (kip->nused == 0)
	{
		/*
		 * Page is no longer in use.  Free it unless
		 * it's the last one.  We keep the last one
		 * so as not to have to set it up again the
		 * next time somebody inserts a probe.
		 */
		hlist_del (&kip->hlist);
		if (!task && hlist_empty (page_list))
		{
			INIT_HLIST_NODE (&kip->hlist);
			hlist_add_head (&kip->hlist, page_list);
		}
		else
		{
			if(task){
				//E. G.: This code provides kernel dump because of rescheduling while atomic. 
				//As workaround, this code was commented. In this case we will have memory leaks 
				//for instrumented process, but instrumentation process should functionate correctly. 
				//Planned that good solution for this problem will be done during redesigning KProbe 
				//for improving supportability and performance.
#if 0
				//printk("collect_one_slot %p/%d\n", task, task->pid);
				mm = get_task_mm (task);
				if (mm){			
					down_write (&mm->mmap_sem);
					do_munmap(mm, (unsigned long)(kip->insns), PAGE_SIZE);
					up_write (&mm->mmap_sem);
					mmput(mm);
				}
#endif
				kip->insns = NULL; //workaround
				kip->tgid = 0;
			}
			else {
				kfree(kip->insns);
			}
			kfree (kip->slot_used);
			kfree (kip);
		}
		return 1;
	}
	return 0;
}

int collect_garbage_slots (struct hlist_head *page_list, struct task_struct *task)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos, *next;
	unsigned slots_per_page = INSNS_PER_PAGE;

	/* Ensure no-one is preepmted on the garbages */
	if (!task && check_safety() != 0)
		return -EAGAIN;

	if(task)
		slots_per_page = INSNS_PER_PAGE/UPROBES_TRAMP_LEN;
	else
		slots_per_page = INSNS_PER_PAGE/KPROBES_TRAMP_LEN;

	hlist_for_each_entry_safe (kip, pos, next, page_list, hlist)
	{
		int i;
		if ((task && (kip->tgid != task->tgid)) || (kip->ngarbage == 0))
			continue;
		kip->ngarbage = 0;	/* we will collect all garbages */
		for (i = 0; i < slots_per_page; i++)
		{
			if (kip->slot_used[i] == SLOT_DIRTY && collect_one_slot (page_list, task, kip, i))
				break;
		}
	}
	if(task)	uprobe_garbage_slots = 0;
	else		kprobe_garbage_slots = 0;
	return 0;
}

void purge_garbage_uslots(struct task_struct *task, int atomic)
{
	if(collect_garbage_slots(&uprobe_insn_pages, task))
		panic("failed to collect garbage slotsfo for task %s/%d/%d", task->comm, task->tgid, task->pid);
}

void free_insn_slot (struct hlist_head *page_list, struct task_struct *task, kprobe_opcode_t *slot, int dirty)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos;
	unsigned slots_per_page = INSNS_PER_PAGE, slot_size = MAX_INSN_SIZE;

	if(task) {	
		slots_per_page = INSNS_PER_PAGE/UPROBES_TRAMP_LEN;
		slot_size = UPROBES_TRAMP_LEN;
	}
	else {
		slots_per_page = INSNS_PER_PAGE/KPROBES_TRAMP_LEN;
		slot_size = KPROBES_TRAMP_LEN;
	}

	DBPRINTF("free_insn_slot: dirty %d, %p/%d", dirty, task, task?task->pid:0);
	hlist_for_each_entry (kip, pos, page_list, hlist)
	{
		DBPRINTF("free_insn_slot: kip->insns=%p slot=%p", kip->insns, slot);
		if ((kip->insns <= slot) && (slot < kip->insns + (INSNS_PER_PAGE * MAX_INSN_SIZE)))
		{
			int i = (slot - kip->insns) / slot_size;
			if (dirty)
			{
				kip->slot_used[i] = SLOT_DIRTY;
				kip->ngarbage++;
			}
			else
			{
				collect_one_slot (page_list, task, kip, i);
			}
			break;
		}
	}

	if (dirty){
		if(task){
			if(++uprobe_garbage_slots > slots_per_page)
				collect_garbage_slots (page_list, task);
		}
		else if(++kprobe_garbage_slots > slots_per_page)
			collect_garbage_slots (page_list, task);
	}
}

struct kprobe *get_kprobe_by_insn_slot (void *addr, int tgid, struct task_struct *ctask)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *retVal = NULL;
	int uprobe_found;

	//TODO: test - two processes invokes instrumented function
	head = &uprobe_insn_slot_table[hash_ptr (addr, KPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu (p, node, head, is_hlist)
	{
		//if looking for kernel probe and this is kernel probe with the same addr OR
		//if looking for the user space probe and this is user space probe probe with the same addr and pid
		DBPRINTF ("get_kprobe: check probe at %p/%p, task %d/%d", addr, p->ainsn.insn, tgid, p->tgid);
		if (p->ainsn.insn == addr)
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
	}

	DBPRINTF ("get_kprobe: probe %p", retVal);
	return retVal;
}


