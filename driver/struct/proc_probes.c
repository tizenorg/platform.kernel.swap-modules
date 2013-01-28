#include "proc_probes.h"
#include <linux/slab.h>
#include <linux/list.h>

extern struct list_head proc_probes_list;

struct proc_probes *proc_p_create(struct dentry* dentry, pid_t tgid)
{
	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	if (proc_p) {
		INIT_LIST_HEAD(&proc_p->list);
		proc_p->tgid = tgid;
		proc_p->dentry = dentry;
		INIT_LIST_HEAD(&proc_p->file_list);
	}

	return proc_p;
}

void proc_p_free(struct proc_probes *proc_p)
{
	struct file_probes *file_p, *n;
	list_for_each_entry_safe(file_p, n, &proc_p->file_list, list) {
		list_del(&file_p->list);
		file_p_del(file_p);
	}

	kfree(proc_p);
}

// TODO: remove "us_proc_info"
#include "../storage.h"
extern inst_us_proc_t us_proc_info;

void proc_p_free_all(void)
{
	if (strcmp(us_proc_info.path,"*") == 0) {
		// app
		proc_p_free(us_proc_info.pp);
		us_proc_info.pp = NULL;
	} else {
		// libonly
		struct proc_probes *proc_p, *n;
		list_for_each_entry_safe(proc_p, n, &proc_probes_list, list) {
			list_del(&proc_p->list);
			proc_p_free(proc_p);
		}
	}
}

static void proc_p_add_file_p(struct proc_probes *proc_p, struct file_probes *file_p)
{
	list_add(&file_p->list, &proc_p->file_list);
}

struct file_probes *proc_p_find_file_p_by_dentry(struct proc_probes *proc_p,
		const char *pach, struct dentry *dentry)
{
	struct file_probes *file_p;

	list_for_each_entry(file_p, &proc_p->file_list, list) {
		if (file_p->dentry == dentry) {
			return file_p;
		}
	}

	file_p = file_p_new(pach, dentry, 10);
	proc_p_add_file_p(proc_p, file_p);

	return file_p;
}

void proc_p_add_dentry_probes(struct proc_probes *proc_p, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt)
{
	int i;
	struct file_probes *file_p = proc_p_find_file_p_by_dentry(proc_p, pach, dentry);

	for (i = 0; i < cnt; ++i) {
		file_p_add_probe(file_p, &ip_d[i]);
	}
}

struct proc_probes *proc_p_copy(struct proc_probes *proc_p, struct task_struct *task)
{
	struct file_probes *file_p;
	struct proc_probes *proc_p_out = proc_p_create(proc_p->dentry, task->tgid);

	list_for_each_entry(file_p, &proc_p->file_list, list) {
		proc_p_add_file_p(proc_p_out, file_p_copy(file_p));
	}

	return proc_p_out;
}

struct file_probes *proc_p_find_file_p(struct proc_probes *proc_p, struct vm_area_struct *vma)
{
	struct file_probes *file_p;

	list_for_each_entry(file_p, &proc_p->file_list, list) {
		if (vma->vm_file->f_dentry == file_p->dentry) {
			return file_p;
		}
	}

	return NULL;
}
