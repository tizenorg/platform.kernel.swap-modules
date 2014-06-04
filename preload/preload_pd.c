#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/hardirq.h>
#include <us_manager/us_manager_common.h>
#include "preload_pd.h"
#include "preload_threads.h"
#include "preload_debugfs.h"
#include "preload_storage.h"
#include "preload_patcher.h"
#include "preload.h"

struct process_data {
    char is_mapped;
	enum preload_state_t state;
	unsigned long loader_base;
	unsigned long handlers_base;
	unsigned long data_page;
	void __user *handle;
	long attempts;
	long refcount;
};

static struct bin_info *handlers_info;



static inline bool check_vma(struct vm_area_struct *vma, struct dentry *dentry)
{
	struct file *file = vma->vm_file;

	return (file && (vma->vm_flags & VM_EXEC) && (file->f_dentry == dentry));
}

static inline enum preload_state_t __get_state(struct process_data *pd)
{
	return pd->state;
}

static inline void __set_state(struct process_data *pd,
				   enum preload_state_t state)
{
	pd->state = state;
}

static inline unsigned long __get_loader_base(struct process_data *pd)
{
	return pd->loader_base;
}

static inline void __set_loader_base(struct process_data *pd,
				     unsigned long addr)
{
	pd->loader_base = addr;
}

static inline unsigned long __get_handlers_base(struct process_data *pd)
{
	return pd->handlers_base;
}

static inline void __set_handlers_base(struct process_data *pd,
				       unsigned long addr)
{
	pd->handlers_base = addr;
}

static inline char __user *__get_path(struct process_data *pd)
{
	return (char *)pd->data_page;
}

static inline unsigned long __get_data_page(struct process_data *pd)
{
	return pd->data_page;
}

static inline void __set_data_page(struct process_data *pd, unsigned long page)
{
	pd->data_page = page;
}

static inline void *__get_handle(struct process_data *pd)
{
	return pd->handle;
}

static inline void __set_handle(struct process_data *pd, void __user *handle)
{
	pd->handle = handle;
}

static inline long __get_attempts(struct process_data *pd)
{
	return pd->attempts;
}

static inline void __set_attempts(struct process_data *pd, long attempts)
{
	pd->attempts = attempts;
}

static inline long __get_refcount(struct process_data *pd)
{
	return pd->refcount;
}

static inline void __set_refcount(struct process_data *pd, long refcount)
{
	pd->refcount = refcount;
}




static unsigned long __find_dentry_base(struct mm_struct *mm,
					struct dentry *dentry)
{
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma, dentry))
			return vma->vm_start;
	}

	return 0;
}

static unsigned long find_dentry_base(struct task_struct *task,
				      struct dentry *dentry)
{
	struct mm_struct *mm = task->mm;
	unsigned long addr;

#ifdef CONFIG_ARM
	down_read(&mm->mmap_sem);
#endif /* CONFIG_ARM */
	addr = __find_dentry_base(mm, dentry);
#ifdef CONFIG_ARM
	up_read(&mm->mmap_sem);
#endif /* CONFIG_ARM */

	return addr;
}

static int __pd_create_on_demand(void)
{
	if (handlers_info == NULL) {
		handlers_info = preload_storage_get_handlers_info();
		if (handlers_info == NULL)
			return -EINVAL;
	}

	return 0;
}



enum preload_state_t preload_pd_get_state(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_state(pd);
}

void preload_pd_set_state(struct process_data *pd, enum preload_state_t state)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	__set_state(pd, state);
}

unsigned long preload_pd_get_loader_base(struct process_data *pd)
{
	if (pd == NULL)
		return ERROR;

	return __get_loader_base(pd);
}

void preload_pd_set_loader_base(struct process_data *pd, unsigned long vaddr)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	__set_loader_base(pd, vaddr);
}

unsigned long preload_pd_get_handlers_base(struct process_data *pd)
{
	if (pd == NULL)
		return 0;

	return __get_handlers_base(pd);
}

void preload_pd_set_handlers_base(struct process_data *pd, unsigned long vaddr)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	__set_handlers_base(pd, vaddr);
}

void preload_pd_put_path(struct process_data *pd)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	if (__get_data_page(pd) == 0)
		return;

	__set_data_page(pd, 0);
}

char __user *preload_pd_get_path(struct process_data *pd)
{
	/* This function should be called only for current */

	struct task_struct *task = current;
	unsigned long page = __get_data_page(pd);
	int ret;

	if (pd == NULL || page == 0)
		return NULL;

    if (pd->is_mapped == 1)
		return __get_path(pd);

	ret = preload_patcher_write_string((void *)page, handlers_info->path,
					   strnlen(handlers_info->path, PATH_MAX),
					   task);
	if (ret <= 0) {
		printk(KERN_ERR PRELOAD_PREFIX "Cannot copy string to user!\n");
        goto get_path_failed;
	}

    pd->is_mapped = 1;

	return __get_path(pd);

get_path_failed:

    return NULL;
}



void *preload_pd_get_handle(struct process_data *pd)
{
	if (pd == NULL)
		return NULL;

	return __get_handle(pd);
}

void preload_pd_set_handle(struct process_data *pd, void __user *handle)
{
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	__set_handle(pd, handle);
}

long preload_pd_get_attempts(struct process_data *pd)
{
	if (pd == NULL)
		return -EINVAL;

	return __get_attempts(pd);
}

void preload_pd_dec_attempts(struct process_data *pd)
{
	long attempts;

	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	attempts = __get_attempts(pd);
	attempts--;
	__set_attempts(pd, attempts);
}

void preload_pd_inc_refs(struct process_data *pd)
{
	long refs;

	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	refs = __get_refcount(pd);
	refs++;
	__set_refcount(pd, refs);
}

void preload_pd_dec_refs(struct process_data *pd)
{
	long refs;

	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n", __LINE__,
               current->tgid, current->comm);
		return;
	}

	refs = __get_refcount(pd);
	refs--;
	__set_refcount(pd, refs);
}

long preload_pd_get_refs(struct process_data *pd)
{
	if (pd == NULL)
		return -EINVAL;

	return __get_refcount(pd);
}

int preload_pd_create_pd(void** target_place, struct task_struct *task)
{
    struct process_data *pd;
    unsigned long page = 0;
	unsigned long base;
	struct dentry *dentry;
	int ret;

	ret = __pd_create_on_demand();
	if (ret)
		goto create_pd_exit;

	pd = kzalloc(sizeof(*pd), GFP_ATOMIC);
	if (pd == NULL) {
		ret = -ENOMEM;
		goto create_pd_exit;
	}

	ret = 0;

	/* 1. check if loader is already mapped */
	dentry = preload_debugfs_get_loader_dentry();
	base = find_dentry_base(task, dentry);
	if (base)
		__set_loader_base(pd, base);

	/* 2. check if handlers are already mapped */
	base = find_dentry_base(task, handlers_info->dentry);
	if (base) {
		__set_handlers_base(pd, base);
		__set_state(pd, LOADED);
	}

	/* 3. map page to store path */
#ifdef CONFIG_ARM
	down_write(&current->mm->mmap_sem);
#endif

	page = swap_do_mmap(NULL, 0, PAGE_SIZE, PROT_READ,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
#ifdef CONFIG_ARM
	up_write(&current->mm->mmap_sem);
#endif
	if (IS_ERR((void *)page)) {
		printk(KERN_ERR PRELOAD_PREFIX "Cannot alloc page for %u\n", task->tgid);
		ret = -ENOMEM;
		goto create_pd_exit;
	}

	pd->is_mapped = 0;

	__set_data_page(pd, page);
	__set_attempts(pd, PRELOAD_MAX_ATTEMPTS);

	*target_place = pd;

create_pd_exit:
	return ret;
}

int preload_pd_init(void)
{
	return 0;
}

void preload_pd_uninit(void)
{
	if (handlers_info)
		preload_storage_put_handlers_info(handlers_info);
	handlers_info = NULL;
}
