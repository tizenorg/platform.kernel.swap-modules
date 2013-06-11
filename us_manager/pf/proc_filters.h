#ifndef _PROC_FILTERS_H
#define _PROC_FILTERS_H

#include <linux/types.h>

struct task_struct;

struct proc_filter {
	struct task_struct *(*call)(struct proc_filter *self,
				    struct task_struct *task);
	void *data;
};

#define check_task_f(filter, task) filter->call(filter, task)

struct proc_filter *create_pf_by_dentry(struct dentry *dentry);
struct proc_filter *create_pf_by_tgid(pid_t tgid);
void free_pf(struct proc_filter *pf);

int check_pf_by_dentry(struct proc_filter *filter, struct dentry *dentry);
int check_pf_by_tgid(struct proc_filter *filter, pid_t tgid);

#endif /* _PROC_FILTERS_H */
