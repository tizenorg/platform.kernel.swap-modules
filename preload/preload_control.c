#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/limits.h>
#include <linux/list.h>

#include <us_manager/sspt/ip.h>

#include "preload.h"

#include "preload_control.h"
#include "preload_probe.h"
#include "preload_module.h"

struct bin_desc {
	struct list_head list;
	struct dentry *dentry;
	char *filename;
};

static LIST_HEAD(target_binaries_list);
static DECLARE_RWSEM(target_binaries_lock);
static int target_binaries_cnt = 0;

static inline struct task_struct *__get_task_struct(void)
{
	return current;
}

static struct bin_desc *__alloc_target_binary(struct dentry *dentry,
					      char *name, int namelen)
{
	struct bin_desc *p = NULL;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return NULL;

	INIT_LIST_HEAD(&p->list);
	p->filename = kmalloc(namelen + 1, GFP_KERNEL);
	if (!p->filename)
		goto fail;
	memcpy(p->filename, name, namelen);
	p->filename[namelen] = '\0';
	p->dentry = dentry;

	return p;
fail:
	kfree(p);
	return NULL;
}

static void __free_target_binary(struct bin_desc *p)
{
	kfree(p->filename);
	kfree(p);
}

static void __free_target_binaries(void)
{
	struct bin_desc *p, *n;

	down_write(&target_binaries_lock);
	list_for_each_entry_safe(p, n, &target_binaries_list, list) {
		list_del(&p->list);
		__free_target_binary(p);
	}
	target_binaries_cnt = 0;
	up_write(&target_binaries_lock);
}

static bool __check_dentry_already_exist(struct dentry *dentry)
{
	struct bin_desc *p;
	bool ret = false;

	down_read(&target_binaries_lock);
	list_for_each_entry(p, &target_binaries_list, list) {
		if (p->dentry == dentry) {
			ret = true;
			goto out;
		}
	}
out:
	up_read(&target_binaries_lock);

	return false;
}

static int __add_target_binary(struct dentry *dentry, char *filename)
{
	struct bin_desc *p;
	size_t len;

	if (__check_dentry_already_exist(dentry)) {
		printk(PRELOAD_PREFIX "Binary already exist\n");
		return EALREADY;
	}

	/* Filename should be < PATH_MAX */
	len = strnlen(filename, PATH_MAX);
	if (len == PATH_MAX)
		return -EINVAL;

	p = __alloc_target_binary(dentry, filename, len);
	if (!p)
		return -ENOMEM;

	down_write(&target_binaries_lock);
	list_add_tail(&p->list, &target_binaries_list);
	target_binaries_cnt++;
	up_write(&target_binaries_lock);

	return 0;
}

static struct dentry *__get_caller_dentry(struct task_struct *task,
					  unsigned long caller)
{
	struct vm_area_struct *vma = NULL;

	if (unlikely(task->mm == NULL))
		goto get_caller_dentry_fail;

	vma = find_vma_intersection(task->mm, caller, caller + 1);
	if (unlikely(vma == NULL || vma->vm_file == NULL))
		goto get_caller_dentry_fail;

	return vma->vm_file->f_dentry;

get_caller_dentry_fail:

	return NULL;
}

static bool __check_if_instrumented(struct task_struct *task,
				    struct dentry *dentry)
{
	return __check_dentry_already_exist(dentry);
}

static bool __is_instrumented(void *caller)
{
	struct task_struct *task = __get_task_struct();
	struct dentry *caller_dentry = __get_caller_dentry(task,
							   (unsigned long) caller);

	if (caller_dentry == NULL)
		return false;

	return __check_if_instrumented(task, caller_dentry);
}


/* Called only form handlers. If we're there, then it is instrumented. */
enum preload_call_type preload_control_call_type_always_inst(void *caller)
{
	if (__is_instrumented(caller))
		return INTERNAL_CALL;

	return EXTERNAL_CALL;

}

enum preload_call_type preload_control_call_type(struct us_ip *ip, void *caller)
{
	if (__is_instrumented(caller))
		return INTERNAL_CALL;

	if (ip->info->pl_i.flags & SWAP_PRELOAD_ALWAYS_RUN)
		return EXTERNAL_CALL;

	return NOT_INSTRUMENTED;
}

int preload_control_add_instrumented_binary(char *filename)
{
	struct dentry *dentry = get_dentry(filename);
	int res = 0;

	if (dentry == NULL)
		return -EINVAL;

	res = __add_target_binary(dentry, filename);
	if (res != 0)
		put_dentry(dentry);

	return res > 0 ? 0 : res;
}

int preload_control_clean_instrumented_bins(void)
{
	__free_target_binaries();

	return 0;
}

unsigned int preload_control_get_bin_names(char ***filenames_p)
{
	unsigned int i, ret = 0;
	struct bin_desc *p;
	char **a = NULL;

	down_read(&target_binaries_lock);
	if (target_binaries_cnt == 0)
		goto out;

	a = kmalloc(sizeof(*a) * target_binaries_cnt, GFP_KERNEL);
	if (!a)
		goto out;

	i = 0;
	list_for_each_entry(p, &target_binaries_list, list) {
		if (i >= target_binaries_cnt)
			break;
		a[i++] = p->filename;
	}

	*filenames_p = a;
	ret = i;
out:
	up_read(&target_binaries_lock);
	return ret;
}

void preload_control_release_bin_names(char ***filenames_p)
{
	kfree(*filenames_p);
}

int preload_control_init(void)
{
	return 0;
}

void preload_control_exit(void)
{
	__free_target_binaries();
}

