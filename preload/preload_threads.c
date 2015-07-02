#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/list.h>
#include "preload.h"
#include "preload_threads.h"
#include "preload_debugfs.h"
#include "preload_patcher.h"
#include "preload_pd.h"

enum {
	DEFAULT_SLOTS_CNT = 10,
};

struct thread_slot {
	struct list_head list;
	struct task_struct *task;
	struct list_head disabled_addrs;	  /* No use for spinlock - called only
						 in one thread */
	unsigned long caller;
	unsigned char call_type;
	bool drop;   /* TODO Workaround, remove when will be possible to install
		     * several us probes at the same addr. */
};

struct disabled_addr {
	struct list_head list;
	unsigned long addr;
};

static LIST_HEAD(thread_slot_list);
static spinlock_t slock;
static unsigned long sflags;


static inline void __lock_init(void)
{
	spin_lock_init(&slock);
}

static inline void __lock(void)
{
	spin_lock_irqsave(&slock, sflags);
}

static inline void __unlock(void)
{
	spin_unlock_irqrestore(&slock, sflags);
}



/* Checks slot for task */
static inline bool __is_slot_for_task(struct thread_slot *slot,
				      struct task_struct *task)
{
	if (slot->task == task)
		return true;

	return false;
}

/* Checks slot if it is free */
static inline bool __is_slot_free(struct thread_slot *slot)
{
	if (slot->task == NULL)
		return true;

	return false;
}

static inline bool __is_addr_found(struct disabled_addr *da,
				   unsigned long addr)
{
	if (da->addr == addr)
		return true;

	return false;
}

static inline void __remove_from_disable_list(struct disabled_addr *da)
{
	list_del(&da->list);
	kfree(da);
}

static inline void __remove_whole_disable_list(struct thread_slot *slot)
{
	struct disabled_addr *da, *n;

	list_for_each_entry_safe(da, n, &slot->disabled_addrs, list)
		__remove_from_disable_list(da);
}

static inline void __init_slot(struct thread_slot *slot)
{
	slot->task = NULL;
	slot->caller = 0;
	slot->call_type = 0;
	slot->drop = false;
	INIT_LIST_HEAD(&slot->disabled_addrs);
}

static inline void __reinit_slot(struct thread_slot *slot)
{
	__remove_whole_disable_list(slot);
	__init_slot(slot);
}

static inline void __set_slot(struct thread_slot *slot,
			      struct task_struct *task, unsigned long caller,
			      unsigned char call_type, bool drop)
{
	slot->task = task;
	slot->caller = caller;
	slot->call_type = call_type;
	slot->drop = drop;
}

static inline int __add_to_disable_list(struct thread_slot *slot,
					unsigned long disable_addr)
{
	struct disabled_addr *da = kmalloc(sizeof(*da), GFP_KERNEL);

	if (da == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&da->list);
	da->addr = disable_addr;
	list_add_tail(&da->list, &slot->disabled_addrs);

	return 0;
}

static inline struct disabled_addr *__find_disabled_addr(struct thread_slot *slot,
							 unsigned long addr)
{
	struct disabled_addr *da;

	list_for_each_entry(da, &slot->disabled_addrs, list)
		if (__is_addr_found(da, addr))
			return da;

	return NULL;
}

/* Adds a new slot */
static inline struct thread_slot *__grow_slot(void)
{
	struct thread_slot *tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);

	if (tmp == NULL)
		return NULL;

	INIT_LIST_HEAD(&tmp->list);
	__init_slot(tmp);
	list_add_tail(&tmp->list, &thread_slot_list);

	return tmp;
}

/* Free slot */
static void __clean_slot(struct thread_slot *slot)
{
	list_del(&slot->list);
	kfree(slot);
}

/* Free all slots. This and all the previous slot functions should be called
   in locks. */
static void __clean_all(void)
{
	struct thread_slot *slot, *n;

	list_for_each_entry_safe(slot, n, &thread_slot_list, list)
		__clean_slot(slot);
}

static inline struct thread_slot *__get_task_slot(struct task_struct *task)
{
	struct thread_slot *slot;

	list_for_each_entry(slot, &thread_slot_list, list)
		if (__is_slot_for_task(slot, task))
			return slot;

	return NULL;
}




int preload_threads_set_data(struct task_struct *task, unsigned long caller,
			     unsigned char call_type,
			     unsigned long disable_addr, bool drop)
{
	struct thread_slot *slot;
	int ret = 0;

	__lock();

	list_for_each_entry(slot, &thread_slot_list, list) {
		if (__is_slot_free(slot)) {
			__set_slot(slot, task, caller, call_type, drop);
			if ((disable_addr != 0) && 
			    (__add_to_disable_list(slot, disable_addr) != 0)) {
				printk(PRELOAD_PREFIX "Cannot alloc memory!\n");
				ret = -ENOMEM;
			}
			goto set_data_done;
		}
	}

	/* If there is no empty slots - grow */
	slot = __grow_slot();
	if (slot == NULL) {
		ret = -ENOMEM;
		goto set_data_done;
	}

	__set_slot(slot, task, caller, call_type, drop);

set_data_done:
	__unlock();

	return ret;
}

int preload_threads_get_caller(struct task_struct *task, unsigned long *caller)
{
	struct thread_slot *slot;
	int ret = 0;

	__lock();

	slot = __get_task_slot(task);
	if (slot != NULL) {
			*caller = slot->caller;
			goto get_caller_done;
	}

	/* If we're here - slot was not found */
	ret = -EINVAL;

get_caller_done:
	__unlock();

	return ret;
}

int preload_threads_get_call_type(struct task_struct *task,
				  unsigned char *call_type)
{
	struct thread_slot *slot;
	int ret = 0;

	__lock();

	slot = __get_task_slot(task);
	if (slot != NULL) {
		*call_type = slot->call_type;
		goto get_call_type_done;
	}

	/* If we're here - slot was not found */
	ret = -EINVAL;

get_call_type_done:
	__unlock();

	return ret;
}

int preload_threads_get_drop(struct task_struct *task, bool *drop)
{
	struct thread_slot *slot;
	int ret = 0;

	__lock();

	slot = __get_task_slot(task);
	if (slot != NULL) {
		*drop = slot->drop;
		goto get_drop_done;
	}

	/* If we're here - slot was not found */
	ret = -EINVAL;

get_drop_done:
	__unlock();

	return ret;
}

bool preload_threads_check_disabled_probe(struct task_struct *task,
					  unsigned long addr)
{
	struct thread_slot *slot;
	bool ret = false;

	__lock();

	slot = __get_task_slot(task);
	if (slot != NULL)
		ret = __find_disabled_addr(slot, addr) == NULL ? false : true;

	__unlock();

	return ret;
}

void preload_threads_enable_probe(struct task_struct *task, unsigned long addr)
{
	struct thread_slot *slot;
	struct disabled_addr *da;

	__lock();

	slot = __get_task_slot(task);
	if (slot == NULL) {
		printk(PRELOAD_PREFIX "Error! Slot not found!\n");
		goto enable_probe_failed;
	}

	da = __find_disabled_addr(slot, addr);
	if (da != NULL)
		__remove_from_disable_list(da);

enable_probe_failed:

	__unlock();
}

int preload_threads_put_data(struct task_struct *task)
{
	struct thread_slot *slot;
	int ret = 0;

	__lock();

	slot = __get_task_slot(task);
	if (slot != NULL) {
		__reinit_slot(slot);
		goto put_data_done;
	}

put_data_done:
	__unlock();

	return ret;
}

/* Allocates slots */
int preload_threads_init(void)
{
	int i, ret = 0;

	__lock_init();

	__lock();

	for (i = 0; i < DEFAULT_SLOTS_CNT; i++) {
		if (__grow_slot() == NULL) {
			ret = -ENOMEM;
			goto init_failed;
		}
	}

	__unlock();

	return 0;

init_failed:

	__clean_all();
	__unlock();

	return ret;
}

/* Cleans slots */
void preload_threads_exit(void)
{
	__lock();
	__clean_all();
	__unlock();
}
