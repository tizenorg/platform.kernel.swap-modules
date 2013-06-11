#ifndef _IMG_IP_H
#define _IMG_IP_H

#include <linux/types.h>

struct img_ip {
	struct list_head list;			/* for img_file */
	unsigned long addr;
};

struct img_ip *create_img_ip(unsigned long addr);
void free_img_ip(struct img_ip *ip);

/* debug */
void img_ip_print(struct img_ip *ip);
/* debug */

#endif /* _IMG_IP_H */
