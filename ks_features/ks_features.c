#include <linux/module.h>
#include <asm/errno.h>
#include <ksyms.h>
#include <dbi_kprobes.h>
#include "ks_features.h"
#include "syscall_list.h"
#include "features_data.c"

/* FIXME: */
#include "../driver/msg/swap_msg.h"

struct ks_probe {
	struct kretprobe rp;
	int counter;
	char *args;
	enum PROBE_SUB_TYPE pst;
};

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
	.rp = CREATE_RP(name),					\
	.counter = 0,						\
	.args = #args__,					\
	.pst = PST_NONE						\
}

static struct ks_probe ksp[] = {
	SYSCALL_LIST
};
#undef X

static const char *get_sys_name(size_t id)
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

/* ========================= HEANDLERS ========================= */
/* FIXME: */
#include <ec_probe.h>
#include <picl.h>
#include <storage.h>
#include "../driver/msg/swap_msg.h"

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs, void *priv_arg)
{
	struct ks_probe *ksp = (struct ks_probe *)priv_arg;
	const char *fmt = ksp->args;
	enum PROBE_SUB_TYPE pst = ksp->pst;

	entry_event(fmt, regs, PT_KS, pst);

	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs, void *priv_arg)
{
	struct ks_probe *ksp = (struct ks_probe *)priv_arg;

	exit_event(regs);

	return 0;
}
/* ========================= HEANDLERS ========================= */



static int register_syscall(size_t id)
{
	int ret;
	printk("register_syscall: %s\n", get_sys_name(id));

	if (ksp[id].rp.kp.addr == NULL)
		return 0;

	ksp[id].rp.entry_handler = entry_handler;
	ksp[id].rp.handler = ret_handler;
	ksp[id].rp.priv_arg = &ksp[id];

	ret = dbi_register_kretprobe(&ksp[id].rp);

	return ret;
}

static int unregister_syscall(size_t id)
{
	printk("unregister_syscall: %s\n", get_sys_name(id));

	if (ksp[id].rp.kp.addr == NULL)
		return 0;

	dbi_unregister_kretprobe(&ksp[id].rp);

	return 0;
}

static void set_spt(struct feature *f, size_t id)
{
	int num = f - features;
	ksp[id].pst = num + 1;
}

static int install_features(struct feature *f)
{
	size_t i, id;

	for (i = 0; i < f->cnt; ++i) {
		id = f->feature_list[i];

		if (get_counter(id) == 0) {
			set_spt(f, id);
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
	unsigned long addr, ni_syscall;
	char *name;

	ni_syscall = swap_ksyms("sys_ni_syscall");

	for (i = 0; i < syscall_name_cnt; ++i) {
		name = get_sys_name(i);
		addr = swap_ksyms(name);
		if (addr == 0) {
			printk("%s() not found\n", name);
			return -EFAULT;
		}

		if (ni_syscall == addr) {
			printk("INFO: %s is not install\n", get_sys_name(i));
			addr = 0;
		}

		ksp[i].rp.kp.addr = addr;
	}

	return 0;
}

static void __exit exit_ks_feature(void)
{
	int id;

	for (id = 0; id < syscall_name_cnt; ++id) {
		if (get_counter(id) > 0)
			unregister_syscall(id);
	}
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
