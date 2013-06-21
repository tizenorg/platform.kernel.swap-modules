#ifndef _US_MANAGER_H
#define _US_MANAGER_H

struct dentry;


int usm_register_probe(struct dentry *dentry, unsigned long offset,
		       void *pre_handler, void *jp_handler, void *rp_handler);
int usm_unregister_probe(struct dentry *dentry, unsigned long offset);

int usm_start(void);
int usm_stop(void);

struct task_struct;

extern void (*ptr_pack_task_event_info)(struct task_struct *task,
					int probe_id,
					int record_type,
					const char *fmt, ...);

#endif /* _US_MANAGER_H */
