#include "img_ip.h"
#include <linux/slab.h>

struct img_ip *create_img_ip(unsigned long addr)
{
	struct img_ip *ip;

	ip = kmalloc(sizeof(*ip), GFP_KERNEL);
	INIT_LIST_HEAD(&ip->list);
	ip->addr = addr;

	return ip;
}

void free_img_ip(struct img_ip *ip)
{
	kfree(ip);
}

/* debug */
void img_ip_print(struct img_ip *ip)
{
	printk("###            addr=%x\n", ip->addr);
}
/* debug */
