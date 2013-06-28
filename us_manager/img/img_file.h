#ifndef _IMG_FILE_H
#define _IMG_FILE_H

#include <linux/types.h>

struct img_file {
	struct list_head list;			/* for img_proc */
	struct dentry *dentry;
	struct list_head ip_list;		/* for img_ip */
};

struct img_file *create_img_file(struct dentry *dentry);
void free_img_file(struct img_file *ip);

int img_file_add_ip(struct img_file *file, unsigned long addr,
		    const char *args);
int img_file_del_ip(struct img_file *file, unsigned long addr);

int img_file_empty(struct img_file *file);

/* debug */
void img_file_print(struct img_file *file);
/* debug */

#endif /* _IMG_FILE_H */

