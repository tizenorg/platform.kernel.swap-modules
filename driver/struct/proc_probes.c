#include "proc_probes.h"
#include <linux/slab.h>
#include <linux/list.h>

extern struct list_head proc_probes_list;

struct sspt_procs *proc_p_create(struct dentry* dentry, pid_t tgid)
{
	struct sspt_procs *procs = kmalloc(sizeof(*procs), GFP_ATOMIC);

	if (procs) {
		INIT_LIST_HEAD(&procs->list);
		procs->tgid = tgid;
		procs->dentry = dentry;
		INIT_LIST_HEAD(&procs->file_list);
	}

	return procs;
}

void proc_p_free(struct sspt_procs *procs)
{
	struct file_probes *file_p, *n;
	list_for_each_entry_safe(file_p, n, &procs->file_list, list) {
		list_del(&file_p->list);
		file_p_del(file_p);
	}

	kfree(procs);
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
		struct sspt_procs *procs, *n;
		list_for_each_entry_safe(procs, n, &proc_probes_list, list) {
			list_del(&procs->list);
			proc_p_free(procs);
		}
	}
}

static void proc_p_add_file_p(struct sspt_procs *procs, struct file_probes *file_p)
{
	list_add(&file_p->list, &procs->file_list);
}

struct file_probes *proc_p_find_file_p_by_dentry(struct sspt_procs *procs,
		const char *pach, struct dentry *dentry)
{
	struct file_probes *file_p;

	list_for_each_entry(file_p, &procs->file_list, list) {
		if (file_p->dentry == dentry) {
			return file_p;
		}
	}

	file_p = file_p_new(pach, dentry, 10);
	proc_p_add_file_p(procs, file_p);

	return file_p;
}

void proc_p_add_dentry_probes(struct sspt_procs *procs, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt)
{
	int i;
	struct file_probes *file_p = proc_p_find_file_p_by_dentry(procs, pach, dentry);

	for (i = 0; i < cnt; ++i) {
		file_p_add_probe(file_p, &ip_d[i]);
	}
}

struct sspt_procs *proc_p_copy(struct sspt_procs *procs, struct task_struct *task)
{
	struct file_probes *file_p;
	struct sspt_procs *procs_out = proc_p_create(procs->dentry, task->tgid);

	list_for_each_entry(file_p, &procs->file_list, list) {
		proc_p_add_file_p(procs_out, file_p_copy(file_p));
	}

	return procs_out;
}

struct file_probes *proc_p_find_file_p(struct sspt_procs *procs, struct vm_area_struct *vma)
{
	struct file_probes *file_p;

	list_for_each_entry(file_p, &procs->file_list, list) {
		if (vma->vm_file->f_dentry == file_p->dentry) {
			return file_p;
		}
	}

	return NULL;
}
