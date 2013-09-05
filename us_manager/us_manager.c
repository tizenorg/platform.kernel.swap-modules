/*
 *  SWAP uprobe manager
 *  modules/us_manager/us_manager.c
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
 * 2013	 Vyacheslav Cherkashin: SWAP us_manager implement
 *
 */

#include <linux/module.h>
#include <linux/mutex.h>
#include "pf/pf_group.h"
#include "sspt/sspt_proc.h"
#include "helper.h"

/* FIXME: move /un/init_msg() elsewhere and remove this include  */
#include <writer/swap_writer_module.h>		/* for /un/init_msg() */


static DEFINE_MUTEX(mutex_inst);
static int flag_inst = 0;


static void do_usm_stop(void)
{
	unregister_helper();
	uninstall_all();
	sspt_proc_free_all();
}

static int do_usm_start(void)
{
	int ret;

	ret = register_helper();
	if (ret)
		return ret;

	install_all();

	return 0;
}

int usm_stop(void)
{
	int ret = 0;

	mutex_lock(&mutex_inst);
	if (flag_inst == 0) {
		printk("US instrumentation is not running!\n");
		ret = -EINVAL;
		goto unlock;
	}

	do_usm_stop();

	flag_inst = 0;
unlock:
	mutex_unlock(&mutex_inst);

	return ret;
}
EXPORT_SYMBOL_GPL(usm_stop);

int usm_start(void)
{
	int ret = -EINVAL;

	mutex_lock(&mutex_inst);
	if (flag_inst) {
		printk("US instrumentation is already run!\n");
		goto unlock;
	}

	ret = do_usm_start();
	if (ret == 0)
		flag_inst = 1;

unlock:
	mutex_unlock(&mutex_inst);

	return ret;
}
EXPORT_SYMBOL_GPL(usm_start);

static int __init init_us_manager(void)
{
	int ret;

	init_msg(32*1024);

	ret = init_helper();
	if (ret)
		return ret;

	return 0;
}

static void __exit exit_us_manager(void)
{
	mutex_lock(&mutex_inst);
	if (flag_inst)
		do_usm_stop();
	mutex_unlock(&mutex_inst);

	uninit_msg();
	uninit_helper();
}

module_init(init_us_manager);
module_exit(exit_us_manager);

MODULE_LICENSE ("GPL");

