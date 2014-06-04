#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

#include <kprobe/swap_kprobes_deps.h>

#include "preload_patcher.h"
#include "preload_debugfs.h"
#include "preload_storage.h"


static inline bool check_vma(struct vm_area_struct *vma, struct dentry *dentry)
{
	struct file *file = vma->vm_file;

	return (file && (vma->vm_flags & VM_EXEC) && (file->f_dentry == dentry));
}


static inline int __patch_proc_mem(struct task_struct *task, unsigned long addr,
				   void *buf, int size)
{
	return write_proc_vm_atomic(task, addr, buf, size);
}

static inline int __read_proc_mem(struct task_struct *task, unsigned long addr,
				  void *value, size_t value_size)
{
	return read_proc_vm_atomic(task, addr, value, value_size);
}




int preload_patcher_patch_proc(void *addr, unsigned long val,
			       struct task_struct *task)
{
	return __patch_proc_mem(task, (unsigned long)addr, &val, sizeof(val));
}

int preload_patcher_write_string(void *addr, char *string, size_t len,
				 struct task_struct *task)
{
	return __patch_proc_mem(task, (unsigned long)addr, string, len);
}

int preload_patcher_get_ul(void *addr, unsigned long *val,
			   struct task_struct *task)
{
	return __read_proc_mem(task, (unsigned long)addr, val, sizeof(*val));
}

int preload_patcher_get_ui(void *addr, unsigned int *val,
			   struct task_struct *task)
{
	return __read_proc_mem(task, (unsigned long)addr, val, sizeof(*val));
}

int preload_patcher_null_mem(void *addr, int size, struct task_struct *task)
{
	char *buf;
	int ret;

	buf = kmalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	memset(buf, 0, size);

	ret = __patch_proc_mem(task, (unsigned long)addr, buf, size);

	kfree(buf);

	return ret;
}
