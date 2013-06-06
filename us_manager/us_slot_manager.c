#include <linux/slab.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/list.h>
#include <dbi_insn_slots.h>
#include <asm/dbi_kprobes.h>

static unsigned long alloc_user_pages(struct task_struct *task, unsigned long len, unsigned long prot, unsigned long flags)
{
	unsigned long ret = 0;
	struct task_struct *otask = current;
	struct mm_struct *mm;
	int atomic = in_atomic();

	mm = atomic ? task->active_mm : get_task_mm(task);
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

static void *sm_alloc_us(struct slot_manager *sm)
{
	struct task_struct *task = sm->data;

	return (void *)alloc_user_pages(task, PAGE_SIZE,
					PROT_EXEC|PROT_READ|PROT_WRITE,
					MAP_ANONYMOUS|MAP_PRIVATE);
}

static void sm_free_us(struct slot_manager *sm, void *ptr)
{
	struct task_struct *task = sm->data;

	/*
	 * E. G.: This code provides kernel dump because of rescheduling while atomic.
	 * As workaround, this code was commented. In this case we will have memory leaks
	 * for instrumented process, but instrumentation process should functionate correctly.
	 * Planned that good solution for this problem will be done during redesigning KProbe
	 * for improving supportability and performance.
	 */
#if 0
	mm = get_task_mm(task);
	if (mm) {
		down_write(&mm->mmap_sem);
		do_munmap(mm, (unsigned long)(ptr), PAGE_SIZE);
		up_write(&mm->mmap_sem);
		mmput(mm);
	}
#endif
	/* FIXME: implement the removal of memory for task */
}

struct slot_manager *create_sm_us(struct task_struct *task)
{
	struct slot_manager *sm = kmalloc(sizeof(*sm), GFP_ATOMIC);
	sm->slot_size = UPROBES_TRAMP_LEN;
	sm->alloc = sm_alloc_us;
	sm->free = sm_free_us;
	INIT_HLIST_NODE(&sm->page_list);
	sm->data = task;

	return sm;
}

void free_sm_us(struct slot_manager *sm)
{
	/* FIXME: free */
}
