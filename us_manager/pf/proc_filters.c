#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include "proc_filters.h"
#include <sspt/sspt.h>

static int check_dentry(struct task_struct *task, struct dentry *dentry)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = task->mm;

	if (mm == NULL) {
		return 0;
	}

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma) && vma->vm_file->f_dentry == dentry) {
			return 1;
		}
	}

	return 0;
}

static struct task_struct *call_by_dentry(struct proc_filter *self,
					 struct task_struct *task)
{
	struct dentry *dentry = (struct dentry *)self->data;

	if (!dentry || check_dentry(task, dentry))
		return task;

	return NULL;
}

static struct task_struct *call_by_tgid(struct proc_filter *self,
				       struct task_struct *task)
{
	pid_t tgid = (pid_t)self->data;

	if (task->tgid == tgid)
		return task;

	return NULL;
}

static struct proc_filter *create_pf(void)
{
	struct proc_filter *pf = kmalloc(sizeof(*pf), GFP_KERNEL);

	return pf;
}

struct proc_filter *create_pf_by_dentry(struct dentry *dentry, void *priv)
{
	struct proc_filter *pf = create_pf();

	pf->call = &call_by_dentry;
	pf->data = (void *)dentry;
	pf->priv = priv;

	return pf;
}
struct proc_filter *create_pf_by_tgid(pid_t tgid, void *priv)
{
	struct proc_filter *pf = create_pf();

	pf->call = &call_by_tgid;
	pf->data = (void *)tgid;
	pf->priv = priv;

	return pf;
}

void free_pf(struct proc_filter *pf)
{
	kfree(pf);
}

int check_pf_by_dentry(struct proc_filter *filter, struct dentry *dentry)
{
	return filter->data == (void *)dentry &&
	       filter->call == &call_by_dentry;
}

int check_pf_by_tgid(struct proc_filter *filter, pid_t tgid)
{
	return filter->data == (void *)tgid && filter->call == &call_by_tgid;
}
