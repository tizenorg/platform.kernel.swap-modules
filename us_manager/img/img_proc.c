#include "img_proc.h"
#include "img_file.h"
#include <linux/slab.h>

struct img_proc *create_img_proc(void)
{
	struct img_proc *proc;

	proc = kmalloc(sizeof(*proc), GFP_KERNEL);
	INIT_LIST_HEAD(&proc->file_list);

	return proc;
}

void free_img_proc(struct img_proc *ip)
{
	/* FIXME: */
}

static void img_add_file_by_list(struct img_proc *proc, struct img_file *file)
{
	list_add(&file->list, &proc->file_list);
}

static void img_del_file_by_list(struct img_file *file)
{
	list_del(&file->list);
}

static struct img_file *find_img_file(struct img_proc *proc, struct dentry *dentry)
{
	struct img_file *file;

	list_for_each_entry(file, &proc->file_list, list) {
		if (file->dentry == dentry)
			return file;
	}

	return NULL;
}

int img_proc_add_ip(struct img_proc *proc, struct dentry *dentry,
		    unsigned long addr, const char *args)
{
	int ret;
	struct img_file *file;

	file = find_img_file(proc, dentry);
	if (file)
		return img_file_add_ip(file, addr, args);

	file = create_img_file(dentry);

	ret = img_file_add_ip(file, addr, args);
	if (ret)
		free_img_file(file);
	else
		img_add_file_by_list(proc, file);

	return ret;
}

int img_proc_del_ip(struct img_proc *proc, struct dentry *dentry, unsigned long addr)
{
	int ret;
	struct img_file *file;

	file = find_img_file(proc, dentry);
	if (file == NULL)
		return -EINVAL;

	ret = img_file_del_ip(file, addr);
	if (ret == 0 && img_file_empty(file)) {
		img_del_file_by_list(file);
		free_img_file(file);
	}

	return ret;
}

/* debug */
void img_proc_print(struct img_proc *proc)
{
	struct img_file *file;

	printk("### img_proc_print:\n");
	list_for_each_entry(file, &proc->file_list, list) {
		img_file_print(file);
	}
}
/* debug */
