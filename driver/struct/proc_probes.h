#ifndef __PROC_PROBES__
#define __PROC_PROBES__

#include <linux/types.h>
#include "file_probes.h"

struct proc_probes {
	struct list_head list;
	pid_t tgid;
	struct dentry *dentry;
	struct list_head file_list;
};


struct proc_probes *proc_p_create(struct dentry* dentry, pid_t tgid);
struct proc_probes *proc_p_copy(struct proc_probes *proc_p, struct task_struct *task);
void proc_p_free(struct proc_probes *proc_p);
void proc_p_free_all(void);

void proc_p_add_dentry_probes(struct proc_probes *proc_p, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt);
struct file_probes *proc_p_find_file_p_by_dentry(struct proc_probes *proc_p,
		const char *pach, struct dentry *dentry);
struct file_probes *proc_p_find_file_p(struct proc_probes *proc_p, struct vm_area_struct *vma);

#endif /* __PROC_PROBES__ */
