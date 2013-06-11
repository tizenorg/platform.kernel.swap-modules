#ifndef _PF_GROUP_H
#define _PF_GROUP_H

#include <linux/types.h>

struct dentry;
struct pf_group;

struct pf_group *get_pf_group_by_dentry(struct dentry *dentry);
struct pf_group *get_pf_group_by_tgid(pid_t tgid);
void put_pf_group(struct pf_group *pfg);

int pf_register_probe(struct pf_group *pfg, struct dentry *dentry,
		      unsigned long offset, void *pre_handler,
		      void *jp_handler, void *rp_handler);
int pf_unregister_probe(struct pf_group *pfg, struct dentry *dentry,
			unsigned long offset);

void install_all(void);
void uninstall_all(void);

void install_page(unsigned long addr);
void uninstall_page(unsigned long addr);

/* debug */
void pfg_print(struct pf_group *pfg);
/* debug */

#endif /* _PF_GROUP_H */
