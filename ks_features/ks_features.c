#include "ks_features.h"
#include "features_data.h"
#include <asm/errno.h>
#include <linux/module.h>

static int register_syscall(size_t id)
{
	printk("register_syscall: %s\n", syscall_name[id]);
	return 0;
}

static int unregister_syscall(size_t id)
{
	printk("unregister_syscall: %s\n", syscall_name[id]);
	return 0;
}

static int install_features(struct feature *f)
{
	size_t i, num;

	for (i = 0; i < f->cnt; ++i) {
		num = f->feature_list[i];

		if (sys_counter[num] == 0) {
			int ret = register_syscall(num);
			if (ret) {
				/* TODO: error */
				return ret;
			}
		}

		++sys_counter[num];
	}

	return 0;
}

static int uninstall_features(struct feature *f)
{
	size_t i, num;

	for (i = 0; i < f->cnt; ++i) {
		num = f->feature_list[i];

		if (sys_counter[num] == 0) {
			/* TODO: error */
			return -EINVAL;
		}

		--sys_counter[num];

		if (sys_counter[num] == 0) {
			int ret = unregister_syscall(num);
			if (ret) {
				/* TODO: error */
				return ret;
			}
		}
	}

	return 0;
}

static struct feature *get_feature(enum feature_id id)
{
	if (id < 0 || id >= (int)feature_cnt)
		return NULL;

	return &features[id];
}

int set_features(enum feature_id id)
{
	struct feature *f = get_feature(id);

	if (f == NULL)
		return -EINVAL;

	return install_features(f);
}

int unset_features(enum feature_id id)
{
	struct feature *f = get_feature(id);

	if (f == NULL)
		return -EINVAL;

	return uninstall_features(f);
}

static int __init init_ks_feature(void)
{
       return 0;
}

static void __exit exit_ks_feature(void)
{
}

module_init(init_ks_feature);
module_exit(exit_ks_feature);

/* debug */
static void print_feature(struct feature *f)
{
	size_t i;

	for (i = 0; i < f->cnt; ++i) {
		printk("    feature[%3u]: %s\n", i, syscall_name[f->feature_list[i]]);
	}
}

void print_features(void)
{
	int i;

	printk("print_features:\n");
	for (i = 0; i < feature_cnt; ++i) {
		printk("feature: %d\n", i);
		print_feature(&features[i]);
	}
}

void print_all_syscall(void)
{
	int i;

	printk("SYSCALL:\n");
	for (i = 0; i < syscall_name_cnt; ++i) {
		printk("    [%2d] %s\n", sys_counter[i], syscall_name[i]);
	}
}
/* debug */
