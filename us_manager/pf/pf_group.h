#ifndef _PF_GROUP_H
#define _PF_GROUP_H

#include <linux/types.h>

struct dentry;
struct pf_group;

struct pf_group *get_pf_group_by_dentry(struct dentry *dentry, void *priv);
struct pf_group *get_pf_group_by_tgid(pid_t tgid, void *priv);
void put_pf_group(struct pf_group *pfg);

int pf_register_probe(struct pf_group *pfg, struct dentry *dentry,
		      unsigned long offset, const char *args);
int pf_unregister_probe(struct pf_group *pfg, struct dentry *dentry,
			unsigned long offset);

void install_all(void);
void uninstall_all(void);

void call_page_fault(struct task_struct *task, unsigned long page_addr);
void call_mm_release(struct task_struct *task);

void uninstall_page(unsigned long addr);

/* debug */
void pfg_print(struct pf_group *pfg);
/* debug */

#endif /* _PF_GROUP_H */
