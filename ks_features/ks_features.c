#include <linux/module.h>
#include <asm/errno.h>
#include <ksyms.h>
#include <dbi_kprobes.h>
#include <writer/swap_writer_module.h>
#include "ks_features.h"
#include "syscall_list.h"
#include "features_data.c"

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

/* ========================= HANDLERS ========================= */
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
/* ========================= HANDLERS ========================= */




/* ====================== SWITCH_CONTEXT ======================= */
static int switch_pre_entry(void *priv_arg, struct pt_regs *regs)
{
	switch_entry(regs);

	return 0;
}

static int switch_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs, void *priv_arg)
{
	switch_exit(regs);

	return 0;
}

struct jprobe switch_jp = {
	.pre_entry = switch_pre_entry,
};

struct kretprobe switch_rp = {
	.handler = switch_ret_handler
};

int init_switch_context(void)
{
	unsigned long addr;

	addr = swap_ksyms("__switch_to");
	if (addr == 0) {
		printk("ERROR: not found '__switch_to'\n");
		return -EINVAL;
	}

	switch_jp.kp.addr = (kprobe_opcode_t *)addr;
	switch_rp.kp.addr = (kprobe_opcode_t *)addr;

	return 0;
}

void exit_switch_context(void)
{
}

static int register_switch_context(void)
{
	int ret;

	ret = dbi_register_jprobe(&switch_jp);
	if (ret) {
		return ret;
	}

	ret = dbi_register_kretprobe(&switch_rp);
	if (ret) {
		dbi_unregister_jprobe(&switch_jp);
	}

	return ret;
}

static int unregister_switch_context(void)
{
	dbi_unregister_kretprobe(&switch_rp);
	dbi_unregister_jprobe(&switch_jp);

	return 0;
}
/* ====================== SWITCH_CONTEXT ======================= */





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
	ksp[id].pst = f - features;
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
				printk("syscall %d install error, ret = %d\n",
				       id, ret);
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
	struct feature *f;

	if (id == FID_SWITCH) {
		return register_switch_context();
	}

	f = get_feature(id);
	if (f == NULL)
		return -EINVAL;

	return install_features(f);
}
EXPORT_SYMBOL_GPL(set_feature);

int unset_feature(enum feature_id id)
{
	struct feature *f;

	if (id == FID_SWITCH) {
		return unregister_switch_context();
	}

	f = get_feature(id);
	if (f == NULL)
		return -EINVAL;

	return uninstall_features(f);
}
EXPORT_SYMBOL_GPL(unset_feature);

static int __init init_ks_feature(void)
{
	int i, ret;
	unsigned long addr, ni_syscall;
	char *name;

	ret = init_switch_context();
	if (ret)
		return ret;

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

	exit_switch_context();
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
