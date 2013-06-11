#include "img_file.h"
#include "img_ip.h"
#include <linux/slab.h>
#include <linux/dcache.h>

struct img_file *create_img_file(struct dentry *dentry)
{
	struct img_file *file;

	file = kmalloc(sizeof(*file), GFP_KERNEL);
	file->dentry = dentry;
	INIT_LIST_HEAD(&file->ip_list);
	INIT_LIST_HEAD(&file->list);

	return file;
}

void free_img_file(struct img_file *file)
{
	/* FIXME: */
}

static void img_add_ip_by_list(struct img_file *file, struct img_ip *ip)
{
	list_add(&ip->list, &file->ip_list);
}

static void img_del_ip_by_list(struct img_ip *ip)
{
	list_del(&ip->list);
}

static struct img_ip *find_img_ip(struct img_file *file, unsigned long addr)
{
	struct img_ip *ip;

	list_for_each_entry(ip, &file->ip_list, list) {
		if (ip->addr == addr)
			return ip;
	}

	return NULL;
}

int img_file_add_ip(struct img_file *file, unsigned long addr)
{
	struct img_ip *ip;

	ip = find_img_ip(file, addr);
	if (ip)
		return -EINVAL;

	ip = create_img_ip(addr);
	img_add_ip_by_list(file, ip);

	return 0;
}

int img_file_del_ip(struct img_file *file, unsigned long addr)
{
	struct img_ip *ip;

	ip = find_img_ip(file, addr);
	if (ip == NULL)
		return -EINVAL;

	img_del_ip_by_list(ip);

	return 0;
}

int img_file_empty(struct img_file *file)
{
	return list_empty(&file->ip_list);
}

/* debug */
void img_file_print(struct img_file *file)
{
	struct img_ip *ip;

	printk("###      d_iname=%s\n", file->dentry->d_iname);

	list_for_each_entry(ip, &file->ip_list, list) {
		img_ip_print(ip);
	}
}
/* debug */
