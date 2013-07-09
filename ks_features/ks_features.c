#include <linux/module.h>
#include <asm/errno.h>
#include <ksyms.h>
#include <dbi_kprobes.h>
#include "ks_features.h"
#include "syscall_list.h"
#include "features_data.c"


struct ks_probe {
	struct jprobe jp;
	struct kretprobe rp;
	int counter;
	char *args;
};

#define CREATE_JP(name)						\
{								\
	.entry = NULL,						\
	.pre_entry = NULL					\
}

#define CREATE_RP(name)						\
{								\
	.entry_handler = NULL,					\
	.handler = NULL						\
}

#define X(name, args) #name
static const char *const syscall_name[] = {
	SYSCALL_LIST
};
#undef X

enum {
	syscall_name_cnt = sizeof(syscall_name) / sizeof(char *)
};


#define X(name, args__)						\
{								\
	.jp = CREATE_JP(name),					\
	.rp = CREATE_RP(name),					\
	.counter = 0,						\
	.args = #args__						\
}

static struct ks_probe ksp[] = {
	SYSCALL_LIST
};
#undef X


static char *get_sys_name(size_t id)
{
	return syscall_name[id];
}

static int get_counter(size_t id)
{
	return ksp[id].counter;
}

static void inc_counter(size_t id)
{
	++ksp[id].counter;
}

static void dec_counter(size_t id)
{
	--ksp[id].counter;
}

static int register_syscall(size_t id)
{
	int ret;
	printk("register_syscall: %s\n", get_sys_name(id));

	ret = dbi_register_jprobe(&ksp[id].jp);
	if (ret)
		return ret;

	ret = dbi_register_kretprobe(&ksp[id].rp);
	if (ret)
		dbi_unregister_jprobe(&ksp[id].jp);

	return ret;
}

static int unregister_syscall(size_t id)
{
	printk("unregister_syscall: %s\n", get_sys_name(id));

	dbi_unregister_kretprobe(&ksp[id].rp);
	dbi_unregister_jprobe(&ksp[id].jp);

	return 0;
}

static int install_features(struct feature *f)
{
	size_t i, id;

	for (i = 0; i < f->cnt; ++i) {
		id = f->feature_list[i];

		if (get_counter(id) == 0) {
			int ret = register_syscall(id);
			if (ret) {
				/* TODO: error */
				return ret;
			}
		}

		inc_counter(id);
	}

	return 0;
}

static int uninstall_features(struct feature *f)
{
	size_t i, id;

	for (i = 0; i < f->cnt; ++i) {
		id = f->feature_list[i];

		if (get_counter(id) == 0) {
			/* TODO: error */
			return -EINVAL;
		}

		dec_counter(id);

		if (get_counter(id) == 0) {
			int ret = unregister_syscall(id);
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

int set_feature(enum feature_id id)
{
	struct feature *f = get_feature(id);

	if (f == NULL)
		return -EINVAL;

	return install_features(f);
}
EXPORT_SYMBOL_GPL(set_feature);

int unset_feature(enum feature_id id)
{
	struct feature *f = get_feature(id);

	if (f == NULL)
		return -EINVAL;

	return uninstall_features(f);
}
EXPORT_SYMBOL_GPL(unset_feature);

static int __init init_ks_feature(void)
{
	int i;
	unsigned long addr;
	char *name;

	for (i = 0; i < syscall_name_cnt; ++i) {
		name = get_sys_name(i);
		addr = swap_ksyms(name);
		if (addr == 0) {
			printk("%s() not found\n", name);
			return -EFAULT;
		}

		ksp[i].jp.kp.addr = ksp[i].rp.kp.addr = addr;
	}

	return 0;
}

static void __exit exit_ks_feature(void)
{
}

module_init(init_ks_feature);
module_exit(exit_ks_feature);

MODULE_LICENSE("GPL");

/* debug */
static void print_feature(struct feature *f)
{
	size_t i;

	for (i = 0; i < f->cnt; ++i) {
		printk("    feature[%3u]: %s\n", i, get_sys_name(f->feature_list[i]));
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
		printk("    [%2d] %s\n", get_counter(i), get_sys_name(i));
	}
}
/* debug */
