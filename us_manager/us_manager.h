#ifndef _US_MANAGER_H
#define _US_MANAGER_H

struct dentry;


int usm_register_probe(struct dentry *dentry, unsigned long offset,
		       void *pre_handler, void *jp_handler, void *rp_handler);
int usm_unregister_probe(struct dentry *dentry, unsigned long offset);

int usm_start(void);
int usm_stop(void);

#endif /* _US_MANAGER_H */
