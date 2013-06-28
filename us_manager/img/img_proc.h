#ifndef _IMG_PROC_H
#define _IMG_PROC_H

#include <linux/types.h>

struct dentry;

struct img_proc {
	struct list_head file_list;
};

struct img_proc *create_img_proc(void);
void free_img_proc(struct img_proc *proc);

int img_proc_add_ip(struct img_proc *proc, struct dentry *dentry,
		    unsigned long addr, const char *args);
int img_proc_del_ip(struct img_proc *proc, struct dentry *dentry, unsigned long addr);

/* debug */
void img_proc_print(struct img_proc *proc);
/* debug */

#endif /* _IMG_PROC_H */
