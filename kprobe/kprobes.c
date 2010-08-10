// src_kprobes.c


#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif

#include <asm/types.h>

#include <linux/hash.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>
//#include <linux/freezer.h>
#include <linux/seq_file.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif
#include <asm-generic/sections.h>
#include <asm/cacheflush.h>
#include <asm/errno.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/highmem.h>	// kmap_atomic, kunmap_atomic, copy_from_user_page, copy_to_user_page
#include <linux/pagemap.h>	// page_cache_release
#include <linux/vmalloc.h>	// vmalloc, vfree
#if defined(CONFIG_X86)
#include <linux/kdebug.h>	// register_die_notifier, unregister_die_notifier
#endif
#include <linux/hugetlb.h>	// follow_hugetlb_page, is_vm_hugetlb_page

#include "kprobes.h"

//#define arch_remove_kprobe(p)	do { } while (0)

#ifdef _DEBUG
extern int nCount;
#endif

/*
static spinlock_t die_notifier_lock = SPIN_LOCK_UNLOCKED;

int src_register_die_notifier(struct notifier_block *nb)
{
	int err = 0;
	unsigned long flags;

	spin_lock_irqsave(&die_notifier_lock, flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
	err = atomic_notifier_chain_register(&panic_notifier_list, nb);
#else
	err = notifier_chain_register(&panic_notifier_list, nb);
#endif
	spin_unlock_irqrestore(&die_notifier_lock, flags);

	return err;
}
*/

int get_user_pages_uprobe(struct task_struct *tsk, struct mm_struct *mm,
			  unsigned long start, int len, int write, int force,
			  struct page **pages, struct vm_area_struct **vmas);
/**
 * hlist_replace_rcu - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * The @old entry will be replaced with the @new entry atomically.
 */
static inline void
src_hlist_replace_rcu (struct hlist_node *old, struct hlist_node *new)
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

#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)


/*
 * Some oddball architectures like 64bit powerpc have function descriptors
 * so this must be overridable.
 */
#ifndef kprobe_lookup_name
#define kprobe_lookup_name(name, addr) \
	addr = ((kprobe_opcode_t *)(kallsyms_lookup_name(name)))
#endif

static struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];
static struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];
static struct hlist_head uprobe_insn_slot_table[KPROBE_TABLE_SIZE];
static atomic_t kprobe_count;

//DEFINE_MUTEX(kprobe_mutex);           /* Protects kprobe_table */
DEFINE_SPINLOCK (kretprobe_lock);	/* Protects kretprobe_inst_table */
static DEFINE_PER_CPU (struct kprobe *, kprobe_instance) = NULL;
unsigned long handled_exceptions;

/* We have preemption disabled.. so it is safe to use __ versions */
static inline void
set_kprobe_instance (struct kprobe *kp)
{
	__get_cpu_var (kprobe_instance) = kp;
}

static inline void
reset_kprobe_instance (void)
{
	__get_cpu_var (kprobe_instance) = NULL;
}

/*
 * This routine is called either:
 * 	- under the kprobe_mutex - during kprobe_[un]register()
 * 				OR
 * 	- with preemption disabled - from arch/xxx/kernel/kprobes.c
 */
struct kprobe __kprobes *
get_kprobe (void *addr, int tgid, struct task_struct *ctask)
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
		ret = get_user_pages_uprobe (ctask, ctask->active_mm, (unsigned long) addr, 1, 0, 0, &tpage, NULL);
		if (ret <= 0)
			DBPRINTF ("get_user_pages for task %d at %p failed!", current->pid, addr);
		else
		{
			paddr = page_address (tpage);
			page_cache_release (tpage);
		}
	}
	//else
	//      DBPRINTF("task %d has no mm!", ctask->pid);

	//TODO: test - two processes invokes instrumented function
	head = &kprobe_table[hash_ptr (addr, KPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu (p, node, head, hlist)
	{
		//if looking for kernel probe and this is kernel probe with the same addr OR
		//if looking for the user space probe and this is user space probe probe with the same addr and pid
		DBPRINTF ("get_kprobe[%d]: check probe at %p/%p, task %d/%d", nCount, addr, p->addr, tgid, p->tgid);
		if (p->addr == addr)
		{
			uprobe_found = 0;
			if (tgid == p->tgid)
				uprobe_found = 1;
			if (!tgid || uprobe_found)
			{
				retVal = p;
				if (tgid)
					DBPRINTF ("get_kprobe[%d]: found user space probe at %p for task %d", nCount, p->addr, p->tgid);
				else
					DBPRINTF ("get_kprobe[%d]: found kernel probe at %p", nCount, p->addr);
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
				DBPRINTF ("get_kprobe[%d]: found user space probe at %p in task %d. possibly for addr %p in task %d", nCount, p->addr, p->tgid, addr, tgid);
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
						ret = get_user_pages_uprobe (task, task->active_mm, (unsigned long) p->addr, 1, 0, 0, &page, &vma);
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
				put_task_struct (task);
				if (ret <= 0)
					continue;
				if (paddr == page_address (page))
				{
					retVal = p;	// we found the probe in other process address space
					DBPRINTF ("get_kprobe[%d]: found user space probe at %p in task %d for addr %p in task %d", nCount, p->addr, p->tgid, addr, tgid);
					panic ("user space probe from another process");
				}
				page_cache_release (page);
				if (retVal)
					break;
			}
		}
	}

	DBPRINTF ("get_kprobe[%d]: probe %p", nCount, retVal);
	return retVal;
}

struct kprobe __kprobes *
get_kprobe_by_insn_slot (void *addr, int tgid, struct task_struct *ctask)
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
		DBPRINTF ("get_kprobe[%d]: check probe at %p/%p, task %d/%d", nCount, addr, p->ainsn.insn, tgid, p->tgid);
		if (p->ainsn.insn == addr)
		{
			uprobe_found = 0;
			if (tgid == p->tgid)
				uprobe_found = 1;
			if (!tgid || uprobe_found)
			{
				retVal = p;
				if (tgid)
					DBPRINTF ("get_kprobe[%d]: found user space probe at %p for task %d", nCount, p->addr, p->tgid);
				else
					DBPRINTF ("get_kprobe[%d]: found kernel probe at %p", nCount, p->addr);
				break;
			}
		}
	}

	DBPRINTF ("get_kprobe[%d]: probe %p", nCount, retVal);
	return retVal;
}

/*
 * Aggregate handlers for multiple kprobes support - these handlers
 * take care of invoking the individual kprobe handlers on p->list
 */
static int __kprobes
aggr_pre_handler (struct kprobe *p, struct pt_regs *regs	/*, 
								   struct vm_area_struct **vma, 
								   struct page **page, unsigned long **kaddr */ )
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

static void __kprobes
aggr_post_handler (struct kprobe *p, struct pt_regs *regs, unsigned long flags)
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

#if 1
static int __kprobes
aggr_fault_handler (struct kprobe *p, struct pt_regs *regs, int trapnr)
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
#endif

static int __kprobes
aggr_break_handler (struct kprobe *p, struct pt_regs *regs	/*, 
								   struct vm_area_struct **vma, 
								   struct page **page, unsigned long **kaddr */ )
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
void __kprobes
kprobes_inc_nmissed_count (struct kprobe *p)
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
struct kretprobe_instance __kprobes *
get_free_rp_inst (struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;
	hlist_for_each_entry (ri, node, &rp->free_instances, uflist) 
		return ri;
	return NULL;
}

/* Called with kretprobe_lock held */
static struct kretprobe_instance __kprobes *
get_used_rp_inst (struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;
	hlist_for_each_entry (ri, node, &rp->used_instances, uflist) return ri;
	return NULL;
}

/* Called with kretprobe_lock held */
void __kprobes
add_rp_inst (struct kretprobe_instance *ri)
{
	/*
	 * Remove rp inst off the free list -
	 * Add it back when probed function returns
	 */
	hlist_del (&ri->uflist);

	/* Add rp inst onto table */
	INIT_HLIST_NODE (&ri->hlist);
	hlist_add_head (&ri->hlist, &kretprobe_inst_table[hash_ptr (ri->task, KPROBE_HASH_BITS)]);

	/* Also add this rp inst to the used list. */
	INIT_HLIST_NODE (&ri->uflist);
	hlist_add_head (&ri->uflist, &ri->rp->used_instances);
}

/* Called with kretprobe_lock held */
void __kprobes
recycle_rp_inst (struct kretprobe_instance *ri, struct hlist_head *head)
{
	/* remove rp inst off the rprobe_inst_table */
	hlist_del (&ri->hlist);
	if (ri->rp)
	{
		/* remove rp inst off the used list */
		hlist_del (&ri->uflist);
		/* put rp inst back onto the free list */
		INIT_HLIST_NODE (&ri->uflist);
		hlist_add_head (&ri->uflist, &ri->rp->free_instances);
	}
	else
		/* Unregistering */
		hlist_add_head (&ri->hlist, head);
}

struct hlist_head __kprobes *
kretprobe_inst_table_head (struct task_struct *tsk)
{
	return &kretprobe_inst_table[hash_ptr (tsk, KPROBE_HASH_BITS)];
}

/*
 * This function is called from finish_task_switch when task tk becomes dead,
 * so that we can recycle any function-return probe instances associated
 * with this task. These left over instances represent probed functions
 * that have been called but will never return.
 */
/*void __kprobes kprobe_flush_task(struct task_struct *tk)
{
	struct kretprobe_instance *ri;
	struct hlist_head *head, empty_rp;
	struct hlist_node *node, *tmp;
	unsigned long flags = 0;

	INIT_HLIST_HEAD(&empty_rp);
	spin_lock_irqsave(&kretprobe_lock, flags);
	head = kretprobe_inst_table_head(tk);
	hlist_for_each_entry_safe(ri, node, tmp, head, hlist) {
		if (ri->task == tk)
			recycle_rp_inst(ri, &empty_rp);
	}
	spin_unlock_irqrestore(&kretprobe_lock, flags);

	hlist_for_each_entry_safe(ri, node, tmp, &empty_rp, hlist) {
		hlist_del(&ri->hlist);
		kfree(ri);
	}
}*/

static inline void
free_rp_inst (struct kretprobe *rp)
{
	struct kretprobe_instance *ri;
	while ((ri = get_free_rp_inst (rp)) != NULL)
	{
		hlist_del (&ri->uflist);
		kfree (ri);
	}
}

/*
 * Keep all fields in the kprobe consistent
 */
static inline void
copy_kprobe (struct kprobe *old_p, struct kprobe *p)
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
static int __kprobes
add_new_kprobe (struct kprobe *old_p, struct kprobe *p)
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

/*
 * Fill in the required fields of the "manager kprobe". Replace the
 * earlier kprobe in the hlist with the manager kprobe
 */
static inline void
add_aggr_kprobe (struct kprobe *ap, struct kprobe *p)
{
	copy_kprobe (p, ap);
	flush_insn_slot (ap);
	ap->addr = p->addr;
	ap->pre_handler = aggr_pre_handler;
	ap->fault_handler = aggr_fault_handler;
	if (p->post_handler)
		ap->post_handler = aggr_post_handler;
	if (p->break_handler)
		ap->break_handler = aggr_break_handler;

	INIT_LIST_HEAD (&ap->list);
	list_add_rcu (&p->list, &ap->list);

	src_hlist_replace_rcu (&p->hlist, &ap->hlist);
}

/*
 * This is the second or subsequent kprobe at the address - handle
 * the intricacies
 */
static int __kprobes
register_aggr_kprobe (struct kprobe *old_p, struct kprobe *p)
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

static int __kprobes
__register_kprobe (struct kprobe *p, unsigned long called_from, int atomic)
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
		kprobe_lookup_name (p->symbol_name, p->addr);
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

static int __kprobes
__register_uprobe (struct kprobe *p, struct task_struct *task, int atomic, unsigned long called_from)
{
	int ret = 0;
	struct kprobe *old_p;

	if (!p->addr)
		return -EINVAL;

	DBPRINTF ("p->addr = 0x%p p = 0x%p\n", p->addr, p);

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
		goto out;
	}
	if ((ret = arch_prepare_uprobe (p, task, atomic)) != 0)
	{
		goto out;
	}

	DBPRINTF ("before out ret = 0x%x\n", ret);

	INIT_HLIST_NODE (&p->hlist);
	hlist_add_head_rcu (&p->hlist, &kprobe_table[hash_ptr (p->addr, KPROBE_HASH_BITS)]);

	INIT_HLIST_NODE (&p->is_hlist);
	hlist_add_head_rcu (&p->is_hlist, &uprobe_insn_slot_table[hash_ptr (p->ainsn.insn, KPROBE_HASH_BITS)]);

	arch_arm_uprobe (p, task);
out:
	DBPRINTF ("out ret = 0x%x\n", ret);

	return ret;
}

void __kprobes
unregister_uprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
	unregister_kprobe (p, task, atomic);
}

int __kprobes
register_kprobe (struct kprobe *p, int atomic)
{
	return __register_kprobe (p, (unsigned long) __builtin_return_address (0), atomic);
}

void __kprobes
unregister_kprobe (struct kprobe *p, struct task_struct *task, int atomic)
{
//      struct module *mod;
	struct kprobe *old_p, *list_p;
	int cleanup_p, pid = 0;

//      mutex_lock(&kprobe_mutex);

	pid = p->tgid;

	old_p = get_kprobe (p->addr, pid, NULL);
	DBPRINTF ("unregister_kprobe p=%p old_p=%p", p, old_p);
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
	DBPRINTF ("unregister_kprobe valid_p");
	if ((old_p == p) || ((old_p->pre_handler == aggr_pre_handler) && 
		(p->list.next == &old_p->list) && (p->list.prev == &old_p->list)))
	{
		/* Only probe on the hash list */
		DBPRINTF ("unregister_kprobe disarm pid=%d", pid);
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
	DBPRINTF ("unregister_kprobe cleanup_p=%d", cleanup_p);
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

int __kprobes
register_ujprobe (struct task_struct *task, struct mm_struct *mm, struct jprobe *jp, int atomic)
{
	int ret = 0;
#ifdef _DEBUG
	gSilent = 0;
#endif
	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_pre_handler;
	jp->kp.break_handler = longjmp_break_handler;
	
	ret = __register_uprobe (&jp->kp, task, atomic,
				    (unsigned long) __builtin_return_address (0));

#ifdef _DEBUG
	gSilent = 1;
#endif
	return ret;
}

void __kprobes
unregister_ujprobe (struct task_struct *task, struct jprobe *jp, int atomic)
{
	unregister_uprobe (&jp->kp, task, atomic);
}

int __kprobes
register_jprobe (struct jprobe *jp, int atomic)
{
	/* Todo: Verify probepoint is a function entry point */
	jp->kp.pre_handler = setjmp_pre_handler;
	jp->kp.break_handler = longjmp_break_handler;

	return __register_kprobe (&jp->kp, (unsigned long) __builtin_return_address (0), atomic);
}

void __kprobes
unregister_jprobe (struct jprobe *jp, int atomic)
{
	unregister_kprobe (&jp->kp, 0, atomic);
}

/*
 * This kprobe pre_handler is registered with every kretprobe. When probe
 * hits it will set up the return probe.
 */
static int __kprobes
pre_handler_kretprobe (struct kprobe *p, struct pt_regs *regs	/*, struct vm_area_struct **vma, 
								   struct page **page, unsigned long **kaddr */ )
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

int __kprobes
register_kretprobe (struct kretprobe *rp, int atomic)
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
	if(rp->kp.addr == sched_addr)
		rp->maxactive = 1000;//max (100, 2 * NR_CPUS);
	else if (rp->maxactive <= 0)
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
			return -ENOMEM;
		}
		INIT_HLIST_NODE (&inst->uflist);
		hlist_add_head (&inst->uflist, &rp->free_instances);
	}

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	rp->nmissed = 0;
	/* Establish function entry probe point */
	if ((ret = __register_kprobe (&rp->kp, (unsigned long) __builtin_return_address (0), atomic)) != 0)
		free_rp_inst (rp);

	DBPRINTF ("addr=%p, *addr=[%lx %lx %lx]", rp->kp.addr, (unsigned long) (*(rp->kp.addr)), (unsigned long) (*(rp->kp.addr + 1)), (unsigned long) (*(rp->kp.addr + 2)));
	if(rp->kp.addr == sched_addr)
		sched_rp = rp;

	return ret;
}

void __kprobes
unregister_kretprobe (struct kretprobe *rp, int atomic)
{
	unsigned long flags;
	struct kretprobe_instance *ri;

	//printk("addr=%p, *addr=[%lx %lx %lx]\n", rp->kp.addr, 
	//               *(rp->kp.addr), *(rp->kp.addr+1), *(rp->kp.addr+2));
	unregister_kprobe (&rp->kp, 0, atomic);

	if(rp->kp.addr == sched_addr)
		sched_rp = NULL;
		
	//printk("addr=%p, *addr=[%lx %lx %lx]\n", rp->kp.addr, 
	//               *(rp->kp.addr), *(rp->kp.addr+1), *(rp->kp.addr+2));
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

int __kprobes
register_uretprobe (struct task_struct *task, struct mm_struct *mm, struct kretprobe *rp, int atomic)
{
	int ret = 0;
	struct kretprobe_instance *inst;
	/*struct page *pages[2] = {0, 0};
	   struct vm_area_struct *vmas[2] = {0, 0};
	   unsigned long *kaddrs[2] = {0, 0}; */
	int i;
#ifdef _DEBUG
	gSilent = 0;
#endif

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
#if 0
	ret = get_user_pages_uprobe (task, mm, (unsigned long) rp->kp.addr, 1, 1, 1, &pages[0], &vmas[0]);
	if (ret <= 0)
	{
		DBPRINTF ("get_user_pages for %p failed!", rp->kp.addr);
		ret = -EFAULT;
		goto out;
	}
	if (atomic)
		kaddrs[0] = kmap_atomic (pages[0], KM_USER0) + ((unsigned long) rp->kp.addr & ~PAGE_MASK);
	else
		kaddrs[0] = kmap (pages[0]) + ((unsigned long) rp->kp.addr & ~PAGE_MASK);
	// if 2nd instruction is on the 2nd page
	if ((((unsigned long) (rp->kp.addr + 1)) & ~PAGE_MASK) == 0)
	{
	  ret = get_user_pages_uprobe (task, mm, (unsigned long) (rp->kp.addr + 1), 1, 1, 1, &pages[1], &vmas[1]);
		if (ret <= 0)
		{
			DBPRINTF ("get_user_pages for %p failed!", rp->kp.addr + 1);
			ret = -EFAULT;
			goto out;
		}
		if (atomic)
			kaddrs[1] = kmap_atomic (pages[1], KM_USER1) + ((unsigned long) (rp->kp.addr + 1) & ~PAGE_MASK);
		else
			kaddrs[1] = kmap (pages[1]) + ((unsigned long) (rp->kp.addr + 1) & ~PAGE_MASK);
	}
	else
	{
		// 2nd instruction is on the 1st page too
		vmas[1] = vmas[0];
		pages[1] = pages[0];
		kaddrs[1] = kaddrs[0] + 1;
	}
#endif
	/* Establish function exit probe point */
	if ((ret = arch_prepare_uretprobe (rp, task/*vmas, pages, kaddrs */ )) != 0)
		goto out;
	/* Establish function entry probe point */
	if ((ret = __register_uprobe (&rp->kp, task, atomic,
					 (unsigned long) __builtin_return_address (0))) != 0)
	{
		free_rp_inst (rp);
		goto out;
	}
	  
	arch_arm_uretprobe (rp, task);//vmas[1], pages[1], kaddrs[1]);
#if 0
	if (atomic)
		set_page_dirty (pages[1]);
	else
		set_page_dirty_lock (pages[1]);
#endif
      out:
#if 0
	if (pages[0])
	{
		if (kaddrs[0])
		{
			if (atomic)
				kunmap_atomic (kaddrs[0] - ((unsigned long) rp->kp.addr & ~PAGE_MASK), KM_USER0);
			else
				kunmap (pages[0]);
		}
		page_cache_release (pages[0]);
	}
	if ((pages[0] != pages[1]))
	{
		if (pages[1])
		{
			if (kaddrs[1])
			{
				if (atomic)
					kunmap_atomic (kaddrs[1] - ((unsigned long) (rp->kp.addr + 1) & ~PAGE_MASK), KM_USER1);
				else
					kunmap (pages[1]);
			}
			page_cache_release (pages[1]);
		}
	}
	/*else if( (pages[0] != pages[2]) ){
	   if(pages[2]){
	   if(kaddrs[2]) {
	   if (atomic) kunmap_atomic(kaddrs[2], KM_USER1);
	   else        kunmap(pages[2]);
	   }
	   page_cache_release(pages[2]);
	   }
	   } */
#endif

#ifdef _DEBUG
	gSilent = 1;
#endif
	return ret;
}

static struct kretprobe *__kprobes
clone_kretprobe (struct kretprobe *rp)
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

void __kprobes
unregister_uretprobe (struct task_struct *task, struct kretprobe *rp, int atomic)
{
	//int ret = 0;
	unsigned long flags;
	struct kretprobe_instance *ri;
	struct kretprobe *rp2 = NULL;
	/*struct mm_struct *mm;
	   struct page *pages[2] = {0, 0};
	   struct vm_area_struct *vmas[2] = {0, 0};
	   unsigned long *kaddrs[2] = {0, 0}; */

#ifdef _DEBUG
	gSilent = 0;
#endif
#if 0
	mm = atomic ? task->active_mm : get_task_mm (task);
	if (!mm)
	{
		DBPRINTF ("task %u has no mm!", task->pid);
#ifdef _DEBUG
		gSilent = 1;
#endif
		return;
	}
	down_read (&mm->mmap_sem);
	ret = get_user_pages_uprobe (task, mm, (unsigned long) rp->kp.addr, 1, 1, 1, &pages[0], &vmas[0]);

	if (ret <= 0)
	{
		DBPRINTF ("get_user_pages for %p failed!", rp->kp.addr);
		goto out;
	}
	if (atomic)
		kaddrs[0] = kmap_atomic (pages[0], KM_USER0) + ((unsigned long) rp->kp.addr & ~PAGE_MASK);
	else
		kaddrs[0] = kmap (pages[0]) + ((unsigned long) rp->kp.addr & ~PAGE_MASK);
	if ((((unsigned long) (rp->kp.addr + 1)) & ~PAGE_MASK) == 0)
	{
	  
	  ret = get_user_pages_uprobe (task, mm, (unsigned long) (rp->kp.addr + 1), 1, 1, 1, &pages[1], &vmas[1]);
		if (ret <= 0)
		{
			DBPRINTF ("get_user_pages for %p failed!", rp->kp.addr + 1);
			goto out;
		}
		if (atomic)
			kaddrs[1] = kmap_atomic (pages[1], KM_USER1) + ((unsigned long) (rp->kp.addr + 1) & ~PAGE_MASK);
		else
			kaddrs[1] = kmap (pages[1]) + ((unsigned long) (rp->kp.addr + 1) & ~PAGE_MASK);
	}
	else
	{
		vmas[1] = vmas[0];
		pages[1] = pages[0];
		kaddrs[1] = kaddrs[0] + 1;
	}

	/* No race here */
	DBPRINTF ("unregister_uretprobe1 addr %p [%lx %lx]", rp->kp.addr, *kaddrs[0], *kaddrs[1]);
#endif
	spin_lock_irqsave (&kretprobe_lock, flags);
	if (hlist_empty (&rp->used_instances))
	{
		// if there are no used retprobe instances (i.e. function is not entered) - disarm retprobe
		arch_disarm_uretprobe (rp, task);//vmas[1], pages[1], kaddrs[1]);
#if 0
		if (atomic)
			set_page_dirty (pages[1]);
		else
			set_page_dirty_lock (pages[1]);
#endif
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
	//DBPRINTF("unregister_uretprobe3 addr %p [%lx %lx]", 
	//              rp->kp.addr, *kaddrs[0], *kaddrs[1]);
#if 0
      out:
	if (pages[0])
	{
		if (kaddrs[0])
		{
			if (atomic)
				kunmap_atomic (kaddrs[0] - ((unsigned long) rp->kp.addr & ~PAGE_MASK), KM_USER0);
			else
				kunmap (pages[0]);
		}
		page_cache_release (pages[0]);
	}
	if (pages[1] && (pages[0] != pages[1]))
	{
		if (kaddrs[1])
		{
			if (atomic)
				kunmap_atomic (kaddrs[1] - ((unsigned long) (rp->kp.addr + 1) & ~PAGE_MASK), KM_USER1);
			else
				kunmap (pages[1]);
		}
		page_cache_release (pages[1]);
	}
	if (!atomic)
	{
		up_read (&mm->mmap_sem);
		mmput (mm);
	}
#endif
#ifdef _DEBUG
	gSilent = 1;
#endif
}

void __kprobes
unregister_all_uprobes (struct task_struct *task, int atomic)
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
}


#define GUP_FLAGS_WRITE                  0x1
#define GUP_FLAGS_FORCE                  0x2
#define GUP_FLAGS_IGNORE_VMA_PERMISSIONS 0x4
#define GUP_FLAGS_IGNORE_SIGKILL         0x8

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
static inline int use_zero_page(struct vm_area_struct *vma)
{
	/*
	 * We don't want to optimize FOLL_ANON for make_pages_present()
	 * when it tries to page in a VM_LOCKED region. As to VM_SHARED,
	 * we want to get the page from the page tables to make sure
	 * that we serialize and update with any other user of that
	 * mapping.
	 */
	if (vma->vm_flags & (VM_LOCKED | VM_SHARED))
		return 0;
	/*
	 * And if we have a fault routine, it's not an anonymous region.
	 */
	return !vma->vm_ops || !vma->vm_ops->fault;
}
#endif

int __get_user_pages_uprobe(struct task_struct *tsk, struct mm_struct *mm,
		     unsigned long start, int len, int flags,
		struct page **pages, struct vm_area_struct **vmas)
{
	int i;
	unsigned int vm_flags = 0;
	int write = !!(flags & GUP_FLAGS_WRITE);
	int force = !!(flags & GUP_FLAGS_FORCE);
	int ignore = !!(flags & GUP_FLAGS_IGNORE_VMA_PERMISSIONS);
	int ignore_sigkill = !!(flags & GUP_FLAGS_IGNORE_SIGKILL);

	if (len <= 0)
		return 0;
	/* 
	 * Require read or write permissions.
	 * If 'force' is set, we only require the "MAY" flags.
	 */
	vm_flags  = write ? (VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	vm_flags &= force ? (VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);
	i = 0;

	do {
		struct vm_area_struct *vma;
		unsigned int foll_flags;

		//vma = find_extend_vma(mm, start);
		vma = find_vma(mm, start);
		if (!vma && in_gate_area(tsk, start)) {
			unsigned long pg = start & PAGE_MASK;
			struct vm_area_struct *gate_vma = get_gate_vma(tsk);
			pgd_t *pgd;
			pud_t *pud;
			pmd_t *pmd;
			pte_t *pte;

			/* user gate pages are read-only */
			if (!ignore && write)
				return i ? : -EFAULT;
			if (pg > TASK_SIZE)
				pgd = pgd_offset_k(pg);
			else
				pgd = pgd_offset_gate(mm, pg);
			BUG_ON(pgd_none(*pgd));
			pud = pud_offset(pgd, pg);
			BUG_ON(pud_none(*pud));
			pmd = pmd_offset(pud, pg);
			if (pmd_none(*pmd))
				return i ? : -EFAULT;
			pte = pte_offset_map(pmd, pg);
			if (pte_none(*pte)) {
				pte_unmap(pte);
				return i ? : -EFAULT;
			}
			if (pages) {
				struct page *page = vm_normal_page(gate_vma, start, *pte);
				pages[i] = page;
				if (page)
					get_page(page);
			}
			pte_unmap(pte);
			if (vmas)
				vmas[i] = gate_vma;
			i++;
			start += PAGE_SIZE;
			len--;
			continue;
		}

		if (!vma ||
		    (vma->vm_flags & (VM_IO | VM_PFNMAP)) ||
		    (!ignore && !(vm_flags & vma->vm_flags)))
			return i ? : -EFAULT;

		if (is_vm_hugetlb_page(vma)) {
#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
		  	i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &len, i);
#else
			i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &len, i, write);
#endif
			continue;
		}

		foll_flags = FOLL_TOUCH;
		if (pages)
			foll_flags |= FOLL_GET;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,30)
		if (!write && use_zero_page(vma))
		  foll_flags |= FOLL_ANON;
#endif
#endif

		do {
			struct page *page;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
			/*
			 * If we have a pending SIGKILL, don't keep faulting
			 * pages and potentially allocating memory, unless
			 * current is handling munlock--e.g., on exit. In
			 * that case, we are not allocating memory.  Rather,
			 * we're only unlocking already resident/mapped pages.
			 */
			if (unlikely(!ignore_sigkill &&
					fatal_signal_pending(current)))
				return i ? i : -ERESTARTSYS;
#endif

			if (write)
				foll_flags |= FOLL_WRITE;

			
			//cond_resched();

			DBPRINTF ("pages = %p vma = %p\n", pages, vma);
			while (!(page = follow_page(vma, start, foll_flags))) {
				int ret;
				ret = handle_mm_fault(mm, vma, start,
						foll_flags & FOLL_WRITE);

#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
				if (ret & VM_FAULT_WRITE)
				  foll_flags &= ~FOLL_WRITE;
				
				switch (ret & ~VM_FAULT_WRITE) {
				case VM_FAULT_MINOR:
				  tsk->min_flt++;
				  break;
				case VM_FAULT_MAJOR:
				  tsk->maj_flt++;
				  break;
				case VM_FAULT_SIGBUS:
				  return i ? i : -EFAULT;
				case VM_FAULT_OOM:
				  return i ? i : -ENOMEM;
				default:
				  BUG();
				}
				
#else
				if (ret & VM_FAULT_ERROR) {
				  if (ret & VM_FAULT_OOM)
				    return i ? i : -ENOMEM;
				  else if (ret & VM_FAULT_SIGBUS)
				    return i ? i : -EFAULT;
				  BUG();
				}
				if (ret & VM_FAULT_MAJOR)
				  tsk->maj_flt++;
				else
				  tsk->min_flt++;
				
				/*
				 * The VM_FAULT_WRITE bit tells us that
				 * do_wp_page has broken COW when necessary,
				 * even if maybe_mkwrite decided not to set
				 * pte_write. We can thus safely do subsequent
				 * page lookups as if they were reads. But only
				 * do so when looping for pte_write is futile:
				 * in some cases userspace may also be wanting
				 * to write to the gotten user page, which a
				 * read fault here might prevent (a readonly
				 * page might get reCOWed by userspace write).
				 */
				if ((ret & VM_FAULT_WRITE) &&
				    !(vma->vm_flags & VM_WRITE))
				  foll_flags &= ~FOLL_WRITE;
				
				//cond_resched();
#endif
				
			}

			if (IS_ERR(page))
				return i ? i : PTR_ERR(page);
			if (pages) {
				pages[i] = page;

#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
				flush_anon_page(page, start);
#else
				flush_anon_page(vma, page, start);
#endif
				flush_dcache_page(page);
			}
			if (vmas)
				vmas[i] = vma;
			i++;
			start += PAGE_SIZE;
			len--;
		} while (len && start < vma->vm_end);
	} while (len);
	return i;
}

int get_user_pages_uprobe(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, int len, int write, int force,
		struct page **pages, struct vm_area_struct **vmas)
{
	int flags = 0;

	if (write)
		flags |= GUP_FLAGS_WRITE;
	if (force)
		flags |= GUP_FLAGS_FORCE;

	return __get_user_pages_uprobe(tsk, mm,
				start, len, flags,
				pages, vmas);
}

int
access_process_vm_atomic (struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
{

	
  	struct mm_struct *mm;
	struct vm_area_struct *vma;
	void *old_buf = buf;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages_uprobe(tsk, mm, addr, 1,
				write, 1, &page, &vma);
		if (ret <= 0) {
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
#ifdef CONFIG_HAVE_IOREMAP_PROT
			vma = find_vma(mm, addr);
			if (!vma)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
#endif
				break;
			bytes = ret;
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);
	mmput(mm);

	return buf - old_buf;

}

#ifdef CONFIG_DEBUG_FS
const char *(*__real_kallsyms_lookup) (unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf);
const char *
kallsyms_lookup (unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf)
{
	return __real_kallsyms_lookup (addr, symbolsize, offset, modname, namebuf);
}

static void __kprobes
report_probe (struct seq_file *pi, struct kprobe *p, const char *sym, int offset, char *modname)
{
	char *kprobe_type;

	if (p->pre_handler == pre_handler_kretprobe)
		if (p->tgid)
			kprobe_type = "ur";
		else
			kprobe_type = "r";
	else if (p->pre_handler == setjmp_pre_handler)
		if (p->tgid)
			kprobe_type = "uj";
		else
			kprobe_type = "j";
	else if (p->tgid)
		kprobe_type = "u";
	else
		kprobe_type = "k";
	if (sym)
		seq_printf (pi, "%p  %s  %s+0x%x  %s\n", p->addr, kprobe_type, sym, offset, (modname ? modname : " "));
	else
		seq_printf (pi, "%p  %s  %p\n", p->addr, kprobe_type, p->addr);
}

static void __kprobes *
kprobe_seq_start (struct seq_file *f, loff_t * pos)
{
	return (*pos < KPROBE_TABLE_SIZE) ? pos : NULL;
}

static void __kprobes *
kprobe_seq_next (struct seq_file *f, void *v, loff_t * pos)
{
	(*pos)++;
	if (*pos >= KPROBE_TABLE_SIZE)
		return NULL;
	return pos;
}

static void __kprobes
kprobe_seq_stop (struct seq_file *f, void *v)
{
	/* Nothing to do */
}

struct us_proc_ip
{
	char *name;
	int installed;
	struct jprobe jprobe;
	struct kretprobe retprobe;
	unsigned long offset;
};

static int __kprobes
show_kprobe_addr (struct seq_file *pi, void *v)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p, *kp;
	const char *sym = NULL;
	unsigned int i = *(loff_t *) v;
	unsigned long size, offset = 0;
	char *modname, namebuf[128];

	head = &kprobe_table[i];
	preempt_disable ();
	hlist_for_each_entry_rcu (p, node, head, hlist)
	{
		/*if(p->pid){
		   struct us_proc_ip *up = NULL;
		   if (p->pre_handler == pre_handler_kretprobe){
		   struct kretprobe *rp = container_of(p, struct kretprobe, kp);
		   up = container_of(rp, struct us_proc_ip, retprobe);
		   }
		   else {//if (p->pre_handler == setjmp_pre_handler){
		   struct jprobe *jp = container_of(p, struct jprobe, kp);
		   up = container_of(jp, struct us_proc_ip, jprobe);
		   }
		   if(up){
		   sym = up->name;
		   printk("show_kprobe_addr: %s\n", sym);
		   }
		   }
		   else */
		sym = kallsyms_lookup ((unsigned long) p->addr, &size, &offset, &modname, namebuf);
		if (p->pre_handler == aggr_pre_handler)
		{
			list_for_each_entry_rcu (kp, &p->list, list) report_probe (pi, kp, sym, offset, modname);
		}
		else
			report_probe (pi, p, sym, offset, modname);
	}
	//seq_printf (pi, "handled exceptions %lu\n", handled_exceptions);
	preempt_enable ();
	return 0;
}

static struct seq_operations kprobes_seq_ops = {
	.start = kprobe_seq_start,
	.next = kprobe_seq_next,
	.stop = kprobe_seq_stop,
	.show = show_kprobe_addr
};

static int __kprobes
kprobes_open (struct inode *inode, struct file *filp)
{
	return seq_open (filp, &kprobes_seq_ops);
}

static struct file_operations debugfs_kprobes_operations = {
	.open = kprobes_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

#ifdef KPROBES_PROFILE
extern unsigned long nCount;
extern struct timeval probe_enter_diff_sum;
static void __kprobes *
kprobe_prof_seq_start (struct seq_file *f, loff_t * pos)
{
	return (*pos < KPROBE_TABLE_SIZE) ? pos : NULL;
}

static void __kprobes *
kprobe_prof_seq_next (struct seq_file *f, void *v, loff_t * pos)
{
	(*pos)++;
	if (*pos >= KPROBE_TABLE_SIZE)
		return NULL;
	return pos;
}

static void __kprobes
kprobe_prof_seq_stop (struct seq_file *f, void *v)
{
}

static void __kprobes
report_probe_prof (struct seq_file *pi, struct kprobe *p, const char *sym, int offset, char *modname)
{
	char *kprobe_type;

	if (p->pre_handler == pre_handler_kretprobe)
		if (p->pid)
			kprobe_type = "ur";
		else
			kprobe_type = "r";
	else if (p->pre_handler == setjmp_pre_handler)
		if (p->pid)
			kprobe_type = "uj";
		else
			kprobe_type = "j";
	else if (p->pid)
		kprobe_type = "u";
	else
		kprobe_type = "k";

	if (sym)
		seq_printf (pi, "%p  %s  %s+0x%x  %s %lu.%06ld\n", p->addr, kprobe_type,
			    sym, offset, (modname ? modname : " "), p->count ? p->hnd_tm_sum.tv_sec / p->count : 0, p->count ? p->hnd_tm_sum.tv_usec / p->count : 0);
	else

		seq_printf (pi, "%p  %s  %p %lu.%06ld\n", p->addr, kprobe_type, p->addr, p->count ? p->hnd_tm_sum.tv_sec / p->count : 0, p->count ? p->hnd_tm_sum.tv_usec / p->count : 0);
}

static int __kprobes
show_kprobe_prof (struct seq_file *pi, void *v)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;	//, *kp;
	const char *sym = NULL;
	unsigned int i = *(loff_t *) v;
	unsigned long size, offset = 0;
	char *modname, namebuf[128];
	static struct timeval utv, ktv;
	static unsigned long ucount, kcount;

	head = &kprobe_table[i];
	preempt_disable ();
	hlist_for_each_entry_rcu (p, node, head, hlist)
	{
		sym = kallsyms_lookup ((unsigned long) p->addr, &size, &offset, &modname, namebuf);
		/*if (p->pre_handler == aggr_pre_handler) {
		   list_for_each_entry_rcu(kp, &p->list, list)
		   report_probe_prof(pi, kp, sym, offset, modname);
		   } else */
		report_probe_prof (pi, p, sym, offset, modname);
		if (p->count)
		{
			if (p->pid)
			{
				set_normalized_timeval (&utv, utv.tv_sec + p->hnd_tm_sum.tv_sec, utv.tv_usec + p->hnd_tm_sum.tv_usec);
				ucount += p->count;
			}
			else
			{
				//seq_printf(pi, "kernel probe handling %lu %lu.%06ld\n", 
				//              p->count, p->hnd_tm_sum.tv_sec, p->hnd_tm_sum.tv_usec); 
				//seq_printf(pi, "kernel probe handling2 %lu %lu.%06ld\n", 
				//              kcount, ktv.tv_sec, ktv.tv_usec);       
				set_normalized_timeval (&ktv, ktv.tv_sec + p->hnd_tm_sum.tv_sec, ktv.tv_usec + p->hnd_tm_sum.tv_usec);
				kcount += p->count;
				//seq_printf(pi, "kernel probe handling3 %lu %lu.%06ld\n", 
				//              kcount, ktv.tv_sec, ktv.tv_usec);       
			}
		}
	}
	if (i == (KPROBE_TABLE_SIZE - 1))
	{
		seq_printf (pi, "Average kernel probe handling %lu.%06ld\n", kcount ? ktv.tv_sec / kcount : 0, kcount ? ktv.tv_usec / kcount : 0);
		seq_printf (pi, "Average user probe handling %lu.%06ld\n", ucount ? utv.tv_sec / ucount : 0, ucount ? utv.tv_usec / ucount : 0);
		seq_printf (pi, "Average probe period %lu.%06ld\n", nCount ? probe_enter_diff_sum.tv_sec / nCount : 0, nCount ? probe_enter_diff_sum.tv_usec / nCount : 0);
		utv.tv_sec = utv.tv_usec = ktv.tv_sec = ktv.tv_usec = 0;
		ucount = kcount = 0;
	}
	preempt_enable ();
	return 0;
}

static struct seq_operations kprobes_prof_seq_ops = {
	.start = kprobe_prof_seq_start,
	.next = kprobe_prof_seq_next,
	.stop = kprobe_prof_seq_stop,
	.show = show_kprobe_prof
};

static int __kprobes
kprobes_prof_open (struct inode *inode, struct file *filp)
{
	return seq_open (filp, &kprobes_prof_seq_ops);
}

static struct file_operations debugfs_kprobes_prof_operations = {
	.open = kprobes_prof_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif

int __kprobes debugfs_kprobe_init (void);
static struct dentry *dbg_dir, *dbg_file;
#ifdef KPROBES_PROFILE
static struct dentry *dbg_file_prof;
#endif

int __kprobes
debugfs_kprobe_init (void)
{
	//struct dentry *dir, *file;

	dbg_dir = debugfs_create_dir ("kprobes", NULL);
	if (!dbg_dir)
		return -ENOMEM;

	dbg_file = debugfs_create_file ("list", 0444, dbg_dir, 0, &debugfs_kprobes_operations);
	if (!dbg_file)
	{
		debugfs_remove (dbg_dir);
		dbg_dir = NULL;
		return -ENOMEM;
	}

#ifdef KPROBES_PROFILE
	dbg_file_prof = debugfs_create_file ("prof", 0444, dbg_dir, 0, &debugfs_kprobes_prof_operations);
	if (!dbg_file_prof)
	{
		debugfs_remove (dbg_file);
		debugfs_remove (dbg_dir);
		dbg_dir = NULL;
		return -ENOMEM;
	}
#endif
	return 0;
}

//late_initcall(debugfs_kprobe_init);
extern unsigned long (*kallsyms_search) (const char *name);
#endif /* CONFIG_DEBUG_FS */

#if defined(CONFIG_X86)
static struct notifier_block kprobe_exceptions_nb = {
	.notifier_call = kprobe_exceptions_notify,
	.priority = INT_MAX
};
#endif

static int __init
init_kprobes (void)
{
	int i, err = 0;

	/* FIXME allocate the probe table, currently defined statically */
	/* initialize all list heads */
	for (i = 0; i < KPROBE_TABLE_SIZE; i++)
	{
		INIT_HLIST_HEAD (&kprobe_table[i]);
		INIT_HLIST_HEAD (&kretprobe_inst_table[i]);
		INIT_HLIST_HEAD (&uprobe_insn_slot_table[i]);
	}
	atomic_set (&kprobe_count, 0);

	err = arch_init_kprobes ();

	DBPRINTF ("init_kprobes: arch_init_kprobes - %d", err);
#if defined(CONFIG_X86)
	if (!err)
		err = register_die_notifier (&kprobe_exceptions_nb);
	DBPRINTF ("init_kprobes: register_die_notifier - %d", err);
#endif // CONFIG_X86

#ifdef CONFIG_DEBUG_FS
	if (!err)
	{
		__real_kallsyms_lookup = (void *) kallsyms_search ("kallsyms_lookup");
		if (!__real_kallsyms_lookup)
		{
			DBPRINTF ("kallsyms_lookup is not found! Oops. Where is the kernel?");
			return -ESRCH;
		}
		err = debugfs_kprobe_init ();
		DBPRINTF ("init_kprobes: debugfs_kprobe_init - %d", err);
	}
#endif /* CONFIG_DEBUG_FS */

	return err;
}

static void __exit
exit_kprobes (void)
{
#ifdef CONFIG_DEBUG_FS
#ifdef KPROBES_PROFILE
	if (dbg_file_prof)
		debugfs_remove (dbg_file_prof);
#endif
	if (dbg_file)
		debugfs_remove (dbg_file);
	if (dbg_dir)
		debugfs_remove (dbg_dir);
#endif /* CONFIG_DEBUG_FS */

#if defined(CONFIG_X86)
	unregister_die_notifier (&kprobe_exceptions_nb);
#endif // CONFIG_X86
	arch_exit_kprobes ();
}

module_init (init_kprobes);
module_exit (exit_kprobes);

EXPORT_SYMBOL_GPL (register_kprobe);
EXPORT_SYMBOL_GPL (unregister_kprobe);
EXPORT_SYMBOL_GPL (register_jprobe);
EXPORT_SYMBOL_GPL (unregister_jprobe);
EXPORT_SYMBOL_GPL (register_ujprobe);
EXPORT_SYMBOL_GPL (unregister_ujprobe);
EXPORT_SYMBOL_GPL (jprobe_return);
EXPORT_SYMBOL_GPL (uprobe_return);
EXPORT_SYMBOL_GPL (register_kretprobe);
EXPORT_SYMBOL_GPL (unregister_kretprobe);
EXPORT_SYMBOL_GPL (register_uretprobe);
EXPORT_SYMBOL_GPL (unregister_uretprobe);
EXPORT_SYMBOL_GPL (unregister_all_uprobes);
EXPORT_SYMBOL_GPL (access_process_vm_atomic);
#if LINUX_VERSION_CODE != KERNEL_VERSION(2,6,23)
EXPORT_SYMBOL_GPL (access_process_vm);
#endif
#ifdef KERNEL_HAS_ISPAGEPRESENT
EXPORT_SYMBOL_GPL (is_page_present);
#else
EXPORT_SYMBOL_GPL (page_present);
#endif

