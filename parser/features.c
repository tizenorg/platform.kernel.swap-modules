#include <linux/types.h>
#include <linux/module.h>
#include "features.h"
#include <ks_features/ks_features.h>

enum features_list {
	syscall_file	= (1 << 10),	/* File operation syscalls tracing */
	syscall_ipc	= (1 << 11),	/* IPC syscall tracing */
	syscall_process	= (1 << 12),	/* Process syscalls tracing */
	syscall_signal	= (1 << 13),	/* Signal syscalls tracing */
	syscall_network	= (1 << 14),	/* Network syscalls tracing */
	syscall_desc	= (1 << 15),	/* Descriptor syscalls tracing */
	context_switch	= (1 << 16),	/* Context switch tracing */
	func_sampling	= (1 << 19)	/* Function sampling */
};

int set_syscall_file(void)
{
	int ret;

	ret = set_feature(FID_FILE);

	return ret;
}

int unset_syscall_file(void)
{
	int ret;

	ret = unset_feature(FID_FILE);

	return ret;
}

int set_syscall_ipc(void)
{
	int ret;

	ret = set_feature(FID_IPC);

	return ret;
}

int unset_syscall_ipc(void)
{
	int ret;

	ret = unset_feature(FID_IPC);

	return ret;
}

int set_syscall_process(void)
{
	int ret;

	ret = set_feature(FID_PROCESS);

	return ret;
}

int unset_syscall_process(void)
{
	int ret;

	ret = unset_feature(FID_PROCESS);

	return ret;
}

int set_syscall_signal(void)
{
	int ret;

	ret = set_feature(FID_SIGNAL);

	return ret;
}

int unset_syscall_signal(void)
{
	int ret;

	ret = unset_feature(FID_SIGNAL);

	return ret;
}

int set_syscall_network(void)
{
	int ret;

	ret = set_feature(FID_NET);

	return ret;
}

int unset_syscall_network(void)
{
	int ret;

	ret = unset_feature(FID_NET);

	return ret;
}

int set_syscall_desc(void)
{
	int ret;

	ret = set_feature(FID_DESC);

	return ret;
}

int unset_syscall_desc(void)
{
	int ret;

	ret = unset_feature(FID_DESC);

	return ret;
}

int set_context_switch(void)
{
	printk("### set_context_switch\n");

	return -EINVAL;
}

int unset_context_switch(void)
{
	printk("### unset_context_switch\n");

	return -EINVAL;
}

int set_func_sampling(void)
{
	printk("### set_func_sampling\n");

	return -EINVAL;
}

int unset_func_sampling(void)
{
	printk("### unset_func_sampling\n");

	return -EINVAL;
}

struct feature_item {
	char *name;
	int (*set)(void);
	int (*unset)(void);
};

static struct feature_item feature_syscall_file = {
	.name = "file operation syscalls",
	.set = set_syscall_file,
	.unset = unset_syscall_file
};

static struct feature_item feature_syscall_ipc = {
	.name = "IPC syscall",
	.set = set_syscall_ipc,
	.unset = unset_syscall_ipc
};

static struct feature_item feature_syscall_process = {
	.name = "process syscalls",
	.set = set_syscall_process,
	.unset = unset_syscall_process
};

static struct feature_item feature_syscall_signal = {
	.name = "signal syscalls",
	.set = set_syscall_signal,
	.unset = unset_syscall_signal
};

static struct feature_item feature_syscall_network = {
	.name = "network syscalls",
	.set = set_syscall_network,
	.unset = unset_syscall_network
};

static struct feature_item feature_syscall_desc = {
	.name = "descriptor syscalls",
	.set = set_syscall_desc,
	.unset = unset_syscall_desc
};

static struct feature_item feature_context_switch = {
	.name = "context switch",
	.set = set_context_switch,
	.unset = unset_context_switch
};

static struct feature_item feature_func_sampling = {
	.name = "function sampling",
	.set = set_func_sampling,
	.unset = unset_func_sampling
};

static struct feature_item *feature_list[] = {
 /*  0 */	NULL,
 /*  1 */	NULL,
 /*  2 */	NULL,
 /*  3 */	NULL,
 /*  4 */	NULL,
 /*  5 */	NULL,
 /*  6 */	NULL,
 /*  7 */	NULL,
 /*  8 */	NULL,
 /*  9 */	NULL,
 /* 10 */	&feature_syscall_file,
 /* 11 */	&feature_syscall_ipc,
 /* 12 */	&feature_syscall_process,
 /* 13 */	&feature_syscall_signal,
 /* 14 */	&feature_syscall_network,
 /* 15 */	&feature_syscall_desc,
 /* 16 */	&feature_context_switch,
 /* 17 */	NULL,
 /* 18 */	NULL,
 /* 19 */	&feature_func_sampling
};

enum {
	SIZE_FEATURE_LIST = sizeof(feature_list) / sizeof(struct feature_item *),
};

static u64 feature_inst = 0;
static u64 feature_mask = 0;

int init_features(void)
{
	int i;
	for (i = 0; i < SIZE_FEATURE_LIST; ++i) {
		printk("### f init_feature_mask[%2d]=%p\n", i, feature_list[i]);
		if (feature_list[i] != NULL) {
			feature_mask |= ((u64)1) << i;
			printk("### f name=%s\n", feature_list[i]->name);
		}
	}

	return 0;
}

void uninit_features(void)
{
}

int set_features(u64 features)
{
	int i, ret;
	u64 feature_XOR;

	features &= feature_mask;
	feature_XOR = features ^ feature_inst;

	for (i = 0; feature_XOR && i < SIZE_FEATURE_LIST; ++i) {
		if ((feature_XOR & 1) && feature_list[i] != NULL) {
			if (features & 1)
				ret = feature_list[i]->set();
			else
				ret = feature_list[i]->unset();

			if (ret) {
				char *func = features & 1 ? "set" : "unset";
				print_err("%s '%s' ret=%d\n",
					  func, feature_list[i]->name, ret);

				return ret;
			}
		}

		features >>= 1;
		feature_XOR >>= 1;
	}

	return 0;
}
