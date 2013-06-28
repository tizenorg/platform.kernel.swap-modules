#include "img_ip.h"
#include <linux/slab.h>

struct img_ip *create_img_ip(unsigned long addr, const char *args)
{
	struct img_ip *ip;
	size_t len;

	ip = kmalloc(sizeof(*ip), GFP_KERNEL);
	INIT_LIST_HEAD(&ip->list);
	ip->addr = addr;

	/* copy args */
	len = strlen(args) + 1;
	ip->args = kmalloc(len, GFP_KERNEL);
	memcpy(ip->args, args, len);

	return ip;
}

void free_img_ip(struct img_ip *ip)
{
	kfree(ip->args);
	kfree(ip);
}

/* debug */
void img_ip_print(struct img_ip *ip)
{
	printk("###            addr=8%x, args=%s\n", ip->addr, ip->args);
}
/* debug */
