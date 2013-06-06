/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/filters/filters_core.c
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
 * 2013         Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 */

#include "filters_core.h"
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>

struct filter_node {
	struct list_head list;
	char *name;
	struct task_filter *tf;
};

static struct task_filter *ts_filter = NULL;
static LIST_HEAD(ts_filter_list);

static struct filter_node *create_filter_node(const char *name, struct task_filter *tf)
{
	struct filter_node *fn = kmalloc(sizeof(*fn), GFP_ATOMIC);

	if (fn) {
		int len = strlen(name) + 1;

		fn->name = kmalloc(len, GFP_ATOMIC);
		if (fn->name == NULL)
			goto free_fn;

		memcpy(fn->name, name, len);
		fn->tf = tf;
		INIT_LIST_HEAD(&fn->list);
	}

	return fn;

free_fn:
	kfree(fn);
	return NULL;
}

static void free_filter_node(struct filter_node *fn)
{
	kfree(fn->name);
	kfree(fn);
}

static struct task_filter *find_filter(const char *name)
{
	struct filter_node *fn, *tmp;

	list_for_each_entry_safe(fn, tmp, &ts_filter_list, list) {
		if (!strcmp(fn->name, name)) {
			return fn->tf;
		}
	}

	return NULL;
}

int register_filter(const char *name, struct task_filter *tf)
{
	struct filter_node *fn;

	if (find_filter(name))
		return -EINVAL;

	fn = create_filter_node(name, tf);
	if (!fn)
		return -ENOMEM;

	list_add_tail(&fn->list, &ts_filter_list);

	return 0;
}

void unregister_filter(const char *name)
{
	struct filter_node *fn, *tmp;

	list_for_each_entry_safe(fn, tmp, &ts_filter_list, list) {
		if (!strcmp(fn->name, name)) {
			struct task_filter *tf = fn->tf;
			if (tf == ts_filter) {
				ts_filter = NULL;
			}

			list_del(&fn->list);
			free_filter_node(fn);

			break;
		}
	}
}

int set_filter(const char *name)
{
	if (name) {
		struct task_filter *tf;

		tf = find_filter(name);
		if (!tf)
			return -EINVAL;

		ts_filter = tf;
	} else {
		ts_filter = NULL;
	}

	return 0;
}

int init_filter(void *data, size_t size)
{
	if (ts_filter) {
		return ts_filter->init(data, size);
	}

	return -EPERM;
}

void uninit_filter(void)
{
	if (ts_filter) {
		ts_filter->uninit();
	}
}

struct task_struct *check_task(struct task_struct *task)
{
	if (task->flags & PF_KTHREAD)
		return NULL;

	if (ts_filter)
		return ts_filter->call(task);

	return task;
}
