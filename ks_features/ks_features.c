/*
 *  SWAP kernel features
 *  modules/ks_features/ks_features.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Samsung Electronics, 2013
 *
 * 2013	 Vyacheslav Cherkashin: SWAP ks_features implement
 *
 */


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
	int sub_type;
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
	.sub_type = PST_NONE					\
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
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = ri->rp;

	if (rp) {
		struct ks_probe *ksp = container_of(rp, struct ks_probe, rp);
		const char *fmt = ksp->args;
		int sub_type = ksp->sub_type;

		entry_event(fmt, regs, PT_KS, sub_type);
	}

	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = ri->rp;

	if (rp) {
		unsigned long func_addr = (unsigned long)rp->kp.addr;
		unsigned long ret_addr = (unsigned long)ri->ret_addr;

		exit_event(regs, func_addr, ret_addr);
	}

	return 0;
}
/* ========================= HANDLERS ========================= */




/* ====================== SWITCH_CONTEXT ======================= */
static int switch_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	switch_entry(regs);

	return 0;
}

static int switch_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	switch_exit(regs);

	return 0;
}

struct kretprobe switch_rp = {
	.entry_handler = switch_entry_handler,
	.handler = switch_ret_handler
};

static DEFINE_MUTEX(mutex_sc_enable);
static int sc_enable = 0;

int init_switch_context(void)
{
	unsigned long addr;

	addr = swap_ksyms("__switch_to");
	if (addr == 0) {
		printk("ERROR: not found '__switch_to'\n");
		return -EINVAL;
	}

	switch_rp.kp.addr = (kprobe_opcode_t *)addr;

	return 0;
}

void exit_switch_context(void)
{
	if (sc_enable)
		dbi_unregister_kretprobe(&switch_rp);
}

static int register_switch_context(void)
{
	int ret = -EINVAL;

	mutex_lock(&mutex_sc_enable);
	if (sc_enable) {
		printk("switch context profiling is already run!\n");
		goto unlock;
	}

	ret = dbi_register_kretprobe(&switch_rp);
	if (ret == 0)
		sc_enable = 1;

unlock:
	mutex_unlock(&mutex_sc_enable);

	return ret;
}

static int unregister_switch_context(void)
{
	int ret = 0;

	mutex_lock(&mutex_sc_enable);
	if (sc_enable == 0) {
		printk("switch context profiling is not running!\n");
		ret = -EINVAL;
		goto unlock;
	}

	dbi_unregister_kretprobe(&switch_rp);

	sc_enable = 0;
unlock:
	mutex_unlock(&mutex_sc_enable);

	return ret;
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

static void set_pst(struct feature *f, size_t id)
{
	ksp[id].sub_type |= f->sub_type;
}

static void unset_pst(struct feature *f, size_t id)
{
	ksp[id].sub_type &= !f->sub_type;
}

static void do_uninstall_features(struct feature *f, size_t i)
{
	int ret;
	size_t id;
	const size_t end = ((size_t) 0) - 1;

	for (; i != end; --i) {
		id = f->feature_list[i];

		if (get_counter(id) == 0) {
			printk("syscall %s not installed\n",
			       get_sys_name(id));
			BUG();
		}

		dec_counter(id);

		if (get_counter(id) == 0) {
			ret = unregister_syscall(id);
			if (ret)
				printk("syscall %s uninstall error, ret=%d\n",
				       get_sys_name(id), ret);

		}

		unset_pst(f, id);
	}
}

static int do_install_features(struct feature *f)
{
	int ret;
	size_t i, id;

	for (i = 0; i < f->cnt; ++i) {
		id = f->feature_list[i];
		set_pst(f, id);

		if (get_counter(id) == 0) {
			ret = register_syscall(id);
			if (ret) {
				printk("syscall %s install error, ret=%d\n",
				       get_sys_name(id), ret);

				do_uninstall_features(f, --i);
				return ret;
			}
		}

		inc_counter(id);
	}

	return 0;
}

static DEFINE_MUTEX(mutex_features);

static int install_features(struct feature *f)
{
	int ret = 0;

	mutex_lock(&mutex_features);
	if (f->enable) {
		printk("energy profiling is already run!\n");
		ret = -EINVAL;
		goto unlock;
	}

	ret = do_install_features(f);

	f->enable = 1;
unlock:
	mutex_unlock(&mutex_features);
	return ret;
}

static int uninstall_features(struct feature *f)
{
	int ret = 0;

	mutex_lock(&mutex_features);
	if (f->enable == 0) {
		printk("feature[%d] is not running!\n", feature_index(f));
		ret = -EINVAL;
		goto unlock;
	}

	do_uninstall_features(f, f->cnt - 1);

	f->enable = 0;
unlock:
	mutex_unlock(&mutex_features);
	return ret;
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

static int init_syscall_features(void)
{
	size_t i;
	unsigned long addr, ni_syscall;
	const char *name;

	ni_syscall = swap_ksyms("sys_ni_syscall");

	for (i = 0; i < syscall_name_cnt; ++i) {
		name = get_sys_name(i);
		addr = swap_ksyms(name);
		if (addr == 0) {
			printk("%s() not found\n", name);
			return -EFAULT;
		}

		if (ni_syscall == addr) {
			printk("INFO: %s is not install\n", name);
			addr = 0;
		}

		ksp[i].rp.kp.addr = (kprobe_opcode_t *)addr;
	}

	return 0;
}

static void uninit_syscall_features(void)
{
	size_t id;

	for (id = 0; id < syscall_name_cnt; ++id) {
		if (get_counter(id) > 0)
			unregister_syscall(id);
	}
}

static int __init init_ks_feature(void)
{
	int ret;

	ret = init_switch_context();
	if (ret)
		return ret;

	ret = init_syscall_features();
	if (ret)
		exit_switch_context();

	return ret;
}

static void __exit exit_ks_feature(void)
{
	uninit_syscall_features();
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
