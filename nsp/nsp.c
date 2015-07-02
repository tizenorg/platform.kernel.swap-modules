/*
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
 * Copyright (C) Samsung Electronics, 2015
 *
 * 2015         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */


#include <linux/module.h>
#include <writer/swap_msg.h>
#include <uprobe/swap_uaccess.h>
#include <us_manager/pf/pf_group.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/probes/probe_info_new.h>
#include "nsp.h"
#include "nsp_msg.h"
#include "nsp_tdata.h"
#include "nsp_print.h"
#include "nsp_debugfs.h"


/* ============================================================================
 * =                                 probes                                   =
 * ============================================================================
 */

/* dlopen@plt */
static int dlopen_eh(struct uretprobe_instance *ri, struct pt_regs *regs);
static int dlopen_rh(struct uretprobe_instance *ri, struct pt_regs *regs);
static struct probe_info_new pin_dlopen = MAKE_URPROBE(dlopen_eh, dlopen_rh, 0);
struct probe_new p_dlopen = {
	.info = &pin_dlopen
};

/* dlsym@plt */
static int dlsym_eh(struct uretprobe_instance *ri, struct pt_regs *regs);
static int dlsym_rh(struct uretprobe_instance *ri, struct pt_regs *regs);
static struct probe_info_new pin_dlsym = MAKE_URPROBE(dlsym_eh, dlsym_rh, 0);
struct probe_new p_dlsym = {
	.info = &pin_dlsym
};

/* main */
static int main_h(struct kprobe *p, struct pt_regs *regs);
static struct probe_info_new pin_main = MAKE_UPROBE(main_h);
static struct probe_info_otg pin_main_otg = {
	.data = &pin_main
};

/* appcore */
static int appcore_efl_main_h(struct kprobe *p, struct pt_regs *regs);
static struct probe_info_new pin_appcore = MAKE_UPROBE(appcore_efl_main_h);
struct probe_new p_appcore = {
	.info = &pin_appcore
};

/* create */
static int create_eh(struct uretprobe_instance *ri, struct pt_regs *regs);
static int create_rh(struct uretprobe_instance *ri, struct pt_regs *regs);
static struct probe_info_new pin_create = MAKE_URPROBE(create_eh, create_rh, 0);
static struct probe_info_otg pin_create_otg = {
	.data = &pin_create
};

/* reset */
static int reset_eh(struct uretprobe_instance *ri, struct pt_regs *regs);
static int reset_rh(struct uretprobe_instance *ri, struct pt_regs *regs);
static struct probe_info_new pin_reset = MAKE_URPROBE(reset_eh, reset_rh, 0);
static struct probe_info_otg pin_reset_otg = {
	.data = &pin_reset
};





/* ============================================================================
 * =                the variables are initialized by the user                 =
 * ============================================================================
 */
static const char *lpad_path;
static struct dentry *lpad_dentry;

static const char *libappcore_path;
static struct dentry *libappcore_dentry;

static struct {
	unsigned long create;
	unsigned long reset;
	unsigned flag_create:1;
	unsigned flag_reset:1;
} cb_offset = {0};

static bool is_init(void)
{
	return lpad_dentry && libappcore_dentry &&
	       cb_offset.flag_create && cb_offset.flag_reset;
}

static int do_set_offset(enum offset_t os, unsigned long offset)
{
	switch (os) {
	case OS_CREATE:
		cb_offset.create = offset;
		cb_offset.flag_create = 1;
		return 0;
	case OS_RESET:
		cb_offset.reset = offset;
		cb_offset.flag_reset = 1;
		return 0;
	default:
		return -EINVAL;
	}

	return -EINVAL;
}

static int do_set_lpad_info(const char *path, unsigned long dlopen,
			    unsigned long dlsym)
{
	struct dentry *dentry;
	const char *new_path;

	dentry = dentry_by_path(path);
	if (dentry == NULL) {
		pr_err("dentry not found (path='%s')\n", path);
		return -EINVAL;
	}

	new_path = kstrdup(path, GFP_KERNEL);
	if (new_path == NULL) {
		pr_err("out of memory\n");
		return -ENOMEM;
	}

	kfree(lpad_path);

	lpad_path = new_path;
	lpad_dentry = dentry;
	p_dlopen.offset = dlopen;
	p_dlsym.offset = dlsym;

	return 0;
}

static int do_set_appcore_info(const char *path,
			       unsigned long appcore_efl_main)
{
	struct dentry *dentry;
	const char *new_path;

	dentry = dentry_by_path(path);
	if (dentry == NULL) {
		pr_err("dentry not found (path='%s')\n", path);
		return -EINVAL;
	}

	new_path = kstrdup(path, GFP_KERNEL);
	if (new_path == NULL) {
		pr_err("out of memory\n");
		return -ENOMEM;
	}

	kfree(libappcore_path);

	libappcore_path = new_path;
	libappcore_dentry = dentry;
	p_appcore.offset = appcore_efl_main;

	return 0;
}





/* ============================================================================
 * =                                nsp_data                                  =
 * ============================================================================
 */
struct nsp_data {
	struct list_head list;

	const char *app_path;
	struct dentry *app_dentry;

	struct pf_group *pfg;
};

static LIST_HEAD(nsp_data_list);

static struct nsp_data *nsp_data_create(const char *app_path)
{
	struct dentry *dentry;
	struct nsp_data *data;

	dentry = dentry_by_path(app_path);
	if (dentry == NULL)
		return ERR_PTR(-ENOENT);

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);

	data->app_path = kstrdup(app_path, GFP_KERNEL);
	if (data->app_path == NULL) {
		kfree(data);
		return ERR_PTR(-ENOMEM);
	}

	data->app_dentry = dentry;
	data->pfg = NULL;

	return data;
}

static void nsp_data_destroy(struct nsp_data *data)
{
	kfree(data->app_path);
	kfree(data);
}

static struct nsp_data *nsp_data_find(const struct dentry *dentry)
{
	struct nsp_data *data;

	list_for_each_entry(data, &nsp_data_list, list) {
		if (data->app_dentry == dentry)
			return data;
	}

	return NULL;
}

static struct nsp_data *nsp_data_find_by_path(const char *path)
{
	struct nsp_data *data;

	list_for_each_entry(data, &nsp_data_list, list) {
		if (strcmp(data->app_path, path) == 0)
			return data;
	}

	return NULL;
}

static void nsp_data_add(struct nsp_data *data)
{
	list_add(&data->list, &nsp_data_list);
}

static void nsp_data_rm(struct nsp_data *data)
{
	list_del(&data->list);
}

static int nsp_data_inst(struct nsp_data *data)
{
	int ret;
	struct pf_group *pfg;

	pfg = get_pf_group_by_dentry(lpad_dentry, (void *)data->app_dentry);
	if (pfg == NULL)
		return -ENOMEM;

	ret = pin_register(&p_dlsym, pfg, lpad_dentry);
	if (ret)
		goto put_g;

	ret = pin_register(&p_dlopen, pfg, lpad_dentry);
	if (ret)
		goto ur_dlsym;

	ret = pin_register(&p_appcore, pfg, libappcore_dentry);
	if (ret)
		goto ur_dlopen;

	data->pfg = pfg;

	return 0;
ur_dlopen:
	pin_unregister(&p_dlopen, pfg, lpad_dentry);
ur_dlsym:
	pin_unregister(&p_dlsym, pfg, lpad_dentry);
put_g:
	put_pf_group(pfg);
	return ret;
}

static void nsp_data_uninst(struct nsp_data *data)
{
	pin_unregister(&p_appcore, data->pfg, libappcore_dentry);
	pin_unregister(&p_dlopen, data->pfg, lpad_dentry);
	pin_unregister(&p_dlsym, data->pfg, lpad_dentry);
	put_pf_group(data->pfg);
	data->pfg = NULL;
}

static int __nsp_add(const char *app_path)
{
	struct nsp_data *data;

	if (nsp_data_find_by_path(app_path))
		return -EEXIST;

	data = nsp_data_create(app_path);
	if (IS_ERR(data))
		return PTR_ERR(data);

	nsp_data_add(data);

	return 0;
}

static int __nsp_rm(const char *path)
{
	struct dentry *dentry;
	struct nsp_data *data;

	dentry = dentry_by_path(path);
	if (dentry == NULL)
		return -ENOENT;

	data = nsp_data_find(dentry);
	if (data == NULL)
		return -ESRCH;

	nsp_data_rm(data);
	nsp_data_destroy(data);

	return 0;
}

static int __nsp_rm_all(void)
{
	struct nsp_data *data, *n;

	list_for_each_entry_safe(data, n, &nsp_data_list, list) {
		nsp_data_rm(data);
		nsp_data_destroy(data);
	}

	return 0;
}

static void __nsp_disabel(void)
{
	struct nsp_data *data;

	list_for_each_entry(data, &nsp_data_list, list) {
		if (data->pfg)
			nsp_data_uninst(data);
	}
}

static int __nsp_enable(void)
{
	int ret;
	struct nsp_data *data;

	list_for_each_entry(data, &nsp_data_list, list) {
		ret = nsp_data_inst(data);
		if (ret)
			goto fail;
	}

	return 0;

fail:
	__nsp_disabel();
	return ret;
}







/* ============================================================================
 * =                             set parameters                               =
 * ============================================================================
 */
#define F_ARG1(m, t, a)		m(t, a)
#define F_ARG2(m, t, a, ...)	m(t, a), F_ARG1(m, __VA_ARGS__)
#define F_ARG3(m, t, a, ...)	m(t, a), F_ARG2(m, __VA_ARGS__)
#define F_ARG(n, m, ...)	F_ARG##n(m, __VA_ARGS__)

#define M_TYPE_AND_ARG(t, a)	t a
#define M_ARG(t, a)		a

#define DECLARE_SAFE_FUNC(n, func_name, do_func, ...)	\
int func_name(F_ARG(n, M_TYPE_AND_ARG,  __VA_ARGS__))	\
{							\
	int ret;					\
	mutex_lock(&stat_mutex);			\
	if (stat == NS_ON) {				\
		ret = -EBUSY;				\
		goto unlock;				\
	}						\
	ret = do_func(F_ARG(n, M_ARG,  __VA_ARGS__));	\
unlock:							\
	mutex_unlock(&stat_mutex);			\
	return ret;					\
}

#define DECLARE_SAFE_FUNC0(name, _do)		DECLARE_SAFE_FUNC(1, name, _do, void, /* */);
#define DECLARE_SAFE_FUNC1(name, _do, ...)	DECLARE_SAFE_FUNC(1, name, _do, __VA_ARGS__);
#define DECLARE_SAFE_FUNC2(name, _do, ...)	DECLARE_SAFE_FUNC(2, name, _do, __VA_ARGS__);
#define DECLARE_SAFE_FUNC3(name, _do, ...)	DECLARE_SAFE_FUNC(3, name, _do, __VA_ARGS__);


static DEFINE_MUTEX(stat_mutex);
static enum nsp_stat stat = NS_OFF;

DECLARE_SAFE_FUNC1(nsp_add, __nsp_add, const char *, app_path);
DECLARE_SAFE_FUNC1(nsp_rm, __nsp_rm, const char *, app_path);
DECLARE_SAFE_FUNC0(nsp_rm_all, __nsp_rm_all);
DECLARE_SAFE_FUNC2(nsp_set_offset, do_set_offset,
		   enum offset_t, os, unsigned long, offset);
DECLARE_SAFE_FUNC3(nsp_set_lpad_info, do_set_lpad_info,
		   const char *, path, unsigned long, dlopen,
		   unsigned long, dlsym);
DECLARE_SAFE_FUNC2(nsp_set_appcore_info, do_set_appcore_info,
		   const char *, path, unsigned long, appcore_efl_main);





/* ============================================================================
 * =                               set stat                                   =
 * ============================================================================
 */
static int set_stat_off(void)
{
	if (stat == NS_OFF)
		return -EINVAL;

	__nsp_disabel();
	tdata_disable();

	stat = NS_OFF;

	return 0;
}

static int set_stat_on(void)
{
	int ret;

	if (is_init() == false)
		return -EPERM;

	if (stat == NS_ON)
		return -EINVAL;

	ret = tdata_enable();
	if (ret)
		return ret;

	__nsp_enable();

	stat = NS_ON;

	return 0;
}

int nsp_set_stat(enum nsp_stat st)
{
	int ret = -EINVAL;

	mutex_lock(&stat_mutex);
	switch (st) {
	case NS_OFF:
		ret = set_stat_off();
		break;
	case NS_ON:
		ret = set_stat_on();
		break;
	}
	mutex_unlock(&stat_mutex);

	return ret;
}

enum nsp_stat nsp_get_stat(void)
{
	return stat;
}





/* ============================================================================
 * =                                handlers                                  =
 * ============================================================================
 */
static int main_h(struct kprobe *p, struct pt_regs *regs)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata) {
		u64 time = swap_msg_current_time();
		u64 exec_time = tdata->time;

		tdata->time = time;
		tdata_put(tdata);

		nsp_msg(NMS_MAPPING, exec_time, time);
	} else {
		nsp_print("can't find mapping begin time\n");
	}

	return 0;
}

static int appcore_efl_main_h(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long *ptr;
	unsigned long appcore_ops_addr;
	unsigned long create_vaddr;
	unsigned long reset_vaddr;
	struct tdata *tdata;
	u64 main_time;
	u64 time;

	tdata = tdata_get(current);
	if (tdata == NULL) {
		nsp_print("can't find 'main' begin time\n");
		return 0;
	}

	/* sent time spent in main() */
	main_time = tdata->time;
	tdata_put(tdata);
	time = swap_msg_current_time();
	nsp_msg(NMS_MAIN, main_time, time);


	/* pointer to appcore_ops struct */
	appcore_ops_addr = swap_get_uarg(regs, 3);

	/* get address create callback */
	ptr = (unsigned long *)(appcore_ops_addr + cb_offset.create);
	if (get_user(create_vaddr, ptr)) {
		nsp_print("failed to dereference a pointer, ptr=%p\n", ptr);
		return 0;
	}

	/* get address reset callback */
	ptr = (unsigned long *)(appcore_ops_addr + cb_offset.reset);
	if (get_user(reset_vaddr, ptr)) {
		nsp_print("failed to dereference a pointer, ptr=%p\n", ptr);
		return 0;
	}

	pin_set_probe(&pin_create_otg, create_vaddr);
	pin_set_probe(&pin_reset_otg, reset_vaddr);

	return 0;
}

static int dlopen_eh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	const char __user *user_s = (const char __user *)swap_get_uarg(regs, 0);
	const char *path;
	struct nsp_data *nsp_data;

	path = strdup_from_user(user_s, GFP_ATOMIC);
	if (path == NULL)
		return 0;

	nsp_data = nsp_data_find_by_path(path);
	if (nsp_data) {
		struct task_struct *task = current;
		struct tdata *tdata;

		tdata = tdata_get(task);
		if (tdata) {
			nsp_print("ERROR: dlopen already cal for '%s'\n", path);
			tdata_put(tdata);
			goto free_path;
		}

		tdata = tdata_create(task);
		if (tdata) {
			tdata->stat = NPS_OPEN_E;
			tdata->time = swap_msg_current_time();
			tdata->nsp_data = nsp_data;
			tdata_put(tdata);
		} else {
			nsp_print("ERROR: out of memory\n");
		}
	}

free_path:
	kfree(path);
	return 0;
}

static int dlopen_rh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata) {
		void *handle;

		handle = (void *)regs_return_value(regs);
		if ((tdata->stat == NPS_OPEN_E) && handle) {
			tdata->stat = NPS_OPEN_R;
			tdata->handle = handle;
			tdata_put(tdata);
		} else {
			tdata_destroy(tdata);
		}
	}

	return 0;
}

static int dlsym_eh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata) {
		const char __user *str = (char __user *)swap_get_uarg(regs, 1);
		const char *name;
		void *handle;

		handle = (void *)swap_get_uarg(regs, 0);
		if (handle == tdata->handle && tdata->stat == NPS_OPEN_R) {
			name = strdup_from_user(str, GFP_ATOMIC);
			if (name && (strcmp(name, "main") == 0))
				tdata->stat = NPS_SYM_E;

			kfree(name);
		}

		tdata_put(tdata);
	}

	return 0;
}

static int dlsym_rh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata) {
		if (tdata->stat == NPS_SYM_E) {
			unsigned long main_vaddr = regs_return_value(regs);

			tdata->stat = NPS_SYM_R;
			pin_set_probe(&pin_main_otg, main_vaddr);
		}

		tdata_put(tdata);
	}

	return 0;
}

static void do_eh(const char *name)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata) {
		tdata->time = swap_msg_current_time();
		tdata_put(tdata);
	} else {
		nsp_print("can't find tdata for '%s'\n", name);
	}
}

static void do_rh(const char *name, enum nsp_msg_stage st)
{
	struct tdata *tdata;

	tdata = tdata_get(current);
	if (tdata) {
		u64 b_time = tdata->time;
		u64 e_time;
		tdata_put(tdata);

		e_time = swap_msg_current_time();
		nsp_msg(st, b_time, e_time);
	} else {
		nsp_print("can't find tdata for '%s'\n", name);
	}
}

static char create_name[] = "create";
static int create_eh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	do_eh(create_name);

	return 0;
}

static int create_rh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	do_rh(create_name, NMS_CREATE);

	return 0;
}

static char reset_name[] = "reset";
static int reset_eh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	do_eh(reset_name);
	return 0;
}

static int reset_rh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	do_rh(reset_name, NMS_RESET);
	return 0;
}





int nsp_init(void)
{
	return 0;
}

void nsp_exit(void)
{
	if (stat == NS_ON)
		set_stat_off();
}
