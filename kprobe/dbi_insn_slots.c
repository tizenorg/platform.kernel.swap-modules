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
 * Copyright (C) Samsung Electronics, 2006-2012
 *
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts
 * 2012         Vyacheslav Cherkashin <v.cherkashin@samsung.com> new memory allocator for slots
 */

#include "dbi_insn_slots.h"
#include "dbi_kdebug.h"

#include <linux/hash.h>
#include <linux/mman.h>
#include <linux/hugetlb.h>

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/module.h>


extern unsigned long do_mmap_pgoff(struct file *file, unsigned long addr,
                        unsigned long len, unsigned long prot,
                        unsigned long flags, unsigned long pgoff);

struct chunk {
	unsigned long *data;
	unsigned long first_available;
	unsigned long count_available;

	spinlock_t    lock;
	unsigned long size;
	unsigned long *index;
};

struct kprobe_insn_page
{
	struct hlist_node hlist;

	struct chunk chunk;
	struct task_struct *task;
};

static void chunk_init(struct chunk *chunk, void *data, size_t size, size_t size_block)
{
	unsigned long i;
	unsigned long *p;

	spin_lock_init(&chunk->lock);
	chunk->data = (unsigned long *)data;
	chunk->first_available = 0;
	chunk->count_available = size / size_block;
	chunk->size = chunk->count_available;

	chunk->index = kmalloc(sizeof(*chunk->index)*chunk->count_available, GFP_ATOMIC);

	p = chunk->index;
	for (i = 0; i != chunk->count_available; ++p) {
		*p = ++i;
	}
}

static void chunk_uninit(struct chunk *chunk)
{
	kfree(chunk->index);
}

static void* chunk_allocate(struct chunk *chunk, size_t size_block)
{
	unsigned long *ret;

	if (!chunk->count_available) {
		return NULL;
	}

	spin_lock(&chunk->lock);
	ret = chunk->data + chunk->first_available*size_block;
	chunk->first_available = chunk->index[chunk->first_available];
	--chunk->count_available;
	spin_unlock(&chunk->lock);

	return ret;
}

static void chunk_deallocate(struct chunk *chunk, void *p, size_t size_block)
{
	unsigned long idx = ((unsigned long *)p - chunk->data)/size_block;

	spin_lock(&chunk->lock);
	chunk->index[idx] = chunk->first_available;
	chunk->first_available = idx;
	++chunk->count_available;
	spin_unlock(&chunk->lock);
}

static inline int chunk_check_ptr(struct chunk *chunk, void *p, size_t size)
{
	if (( chunk->data                             <= (unsigned long *)p) &&
	    ((chunk->data + size/sizeof(chunk->data))  > (unsigned long *)p)) {
		return 1;
	}

	return 0;
}

static inline int chunk_free(struct chunk *chunk)
{
	return (chunk->count_available == chunk->size);
}

static unsigned long alloc_user_pages(struct task_struct *task, unsigned long len, unsigned long prot, unsigned long flags, int atomic)
{
	unsigned long ret = 0;
	struct task_struct *otask = current;
	struct mm_struct *mm;

	mm = atomic ? task->active_mm : get_task_mm (task);
	if (mm) {
		if (!atomic) {
			if (!down_write_trylock(&mm->mmap_sem)) {
				rcu_read_lock();

				up_read(&mm->mmap_sem);
				down_write(&mm->mmap_sem);

				rcu_read_unlock();
			}
		}
		// FIXME: its seems to be bad decision to replace 'current' pointer temporarily
		current_thread_info()->task = task;
		ret = do_mmap_pgoff(NULL, 0, len, prot, flags, 0);
		current_thread_info()->task = otask;
		if (!atomic) {
			downgrade_write (&mm->mmap_sem);
			mmput(mm);
		}
	} else {
		printk("proc %d has no mm", task->tgid);
	}

	return ret;
}

static void *page_new(struct task_struct *task, int atomic)
{
	if (task) {
		return (void *)alloc_user_pages(task, PAGE_SIZE,
				PROT_EXEC|PROT_READ|PROT_WRITE,
				MAP_ANONYMOUS|MAP_PRIVATE/*MAP_SHARED*/, atomic);
	} else {
		return kmalloc(PAGE_SIZE, GFP_ATOMIC);
	}
}

static void page_free(void *data, struct task_struct *task)
{
	if (task) {
		//E. G.: This code provides kernel dump because of rescheduling while atomic.
		//As workaround, this code was commented. In this case we will have memory leaks
		//for instrumented process, but instrumentation process should functionate correctly.
		//Planned that good solution for this problem will be done during redesigning KProbe
		//for improving supportability and performance.
#if 0
		mm = get_task_mm (task);
		if (mm) {
			down_write (&mm->mmap_sem);
			do_munmap(mm, (unsigned long)(data), PAGE_SIZE);
			up_write (&mm->mmap_sem);
			mmput(mm);
		}
#endif
		// FIXME: implement the removal of memory for task
	} else {
		kfree(data);
	}
}

static inline size_t slot_size(struct task_struct *task)
{
	if (task) {
		return UPROBES_TRAMP_LEN;
	} else {
		return KPROBES_TRAMP_LEN;
	}
}

static struct kprobe_insn_page *kip_new(struct task_struct *task, int atomic)
{
	void *data;
	struct kprobe_insn_page *kip;

	kip = kmalloc(sizeof(*kip), GFP_ATOMIC);
	if (kip == NULL) {
		return NULL;
	}

	data = page_new(task, atomic);
	if(data == NULL) {
		kfree(kip);
		return NULL;
	}

	chunk_init(&kip->chunk, data, PAGE_SIZE/sizeof(unsigned long), slot_size(task));
	kip->task = task;

	return kip;
}

static void kip_free(struct kprobe_insn_page * kip)
{
	chunk_uninit(&kip->chunk);
	page_free(kip->chunk.data, kip->task);
	kfree(kip);
}

/**
 * get_us_insn_slot() - Find a slot on an executable page for an instruction.
 * We allocate an executable page if there's no room on existing ones.
 */
kprobe_opcode_t *get_insn_slot(struct task_struct *task, struct hlist_head *page_list, int atomic)
{
	kprobe_opcode_t * free_slot;
	struct kprobe_insn_page *kip;
	struct hlist_node *pos;

	hlist_for_each_entry_rcu(kip, pos, page_list, hlist) {
		if (!task || (kip->task->tgid == task->tgid)) {
			free_slot = chunk_allocate(&kip->chunk, slot_size(task));
			if (free_slot == NULL) {
				break;
			}

			return free_slot;
		}
	}

	kip = kip_new(task, atomic);
	if(kip == NULL)
		return NULL;

	INIT_HLIST_NODE (&kip->hlist);
	hlist_add_head_rcu(&kip->hlist, page_list);

	return chunk_allocate(&kip->chunk, slot_size(task));
}
EXPORT_SYMBOL_GPL(get_insn_slot);

void free_insn_slot(struct hlist_head *page_list, struct task_struct *task, kprobe_opcode_t *slot)
{
	struct kprobe_insn_page *kip;
	struct hlist_node *pos;

	hlist_for_each_entry_rcu(kip, pos, page_list, hlist) {
		if (!(!task || (kip->task->tgid == task->tgid)))
			continue;

		if (!chunk_check_ptr(&kip->chunk, slot, PAGE_SIZE))
			continue;

		chunk_deallocate(&kip->chunk, slot, slot_size(task));

		if (chunk_free(&kip->chunk)) {
			hlist_del_rcu(&kip->hlist);
			kip_free(kip);
		}

		return;
	}

	panic("free_insn_slot: slot=%p is not data base\n", slot);
}
EXPORT_SYMBOL_GPL(free_insn_slot);
