#include <linux/module.h>
#include <sspt/sspt_proc.h>
#include <sspt/sspt_page.h>

static struct sspt_proc *proc_base;

int usm_register_probe(struct dentry *dentry, unsigned long offset,
		       void *pre_handler, void *jp_handler, void *rp_handler)
{
	char *file_name;
	struct sspt_file *file;
	struct ip_data ip_d;

	file_name = dentry->d_iname;
	file = sspt_proc_find_file_or_new(proc_base, dentry, file_name);

	ip_d.flag_retprobe = 1;
	ip_d.got_addr = 0;
	ip_d.jp_handler = jp_handler;
	ip_d.offset = offset;
	ip_d.pre_handler = pre_handler;
	ip_d.rp_handler = rp_handler;

	sspt_file_add_ip(file, &ip_d);

	return 0;
}

int usm_unregister_probe(struct dentry *dentry, unsigned long offset)
{
	struct sspt_file *file;
	struct sspt_page *page;
	struct us_ip *ip;

	file = sspt_proc_find_file(proc_base, dentry);
	if (file == NULL)
		return -EINVAL;

	page = sspt_get_page(file, offset);
	if (page == NULL)
		return -EINVAL;

	ip = sspt_find_ip(page, offset & ~PAGE_MASK);
	if (ip == NULL) {
		sspt_put_page(page);
		return -EINVAL;
	}

	sspt_del_ip(ip);
	sspt_put_page(page);

	return 0;
}

static int __init init_us_manager(void)
{
	proc_base = sspt_proc_create(NULL, NULL);
	return 0;
}

static void __exit exit_us_manager(void)
{
	sspt_proc_free(proc_base);
}

module_init(init_us_manager);
module_exit(exit_us_manager);

MODULE_LICENSE ("GPL");

