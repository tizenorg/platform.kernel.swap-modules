#ifndef __PROC_PROBES__
#define __PROC_PROBES__

#include <linux/types.h>
#include "sspt_file.h"

struct sspt_procs {
	struct list_head list;
	pid_t tgid;
	struct dentry *dentry;
	struct list_head file_list;
};


struct sspt_procs *proc_p_create(struct dentry* dentry, pid_t tgid);
struct sspt_procs *proc_p_copy(struct sspt_procs *procs, struct task_struct *task);
void proc_p_free(struct sspt_procs *procs);
void proc_p_free_all(void);

void proc_p_add_dentry_probes(struct sspt_procs *procs, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt);
struct sspt_file *proc_p_find_file_p_by_dentry(struct sspt_procs *procs,
		const char *pach, struct dentry *dentry);
struct sspt_file *proc_p_find_file_p(struct sspt_procs *procs, struct vm_area_struct *vma);

#endif /* __PROC_PROBES__ */
