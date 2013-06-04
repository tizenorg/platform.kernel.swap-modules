#ifndef _FILTERS_CORE_H
#define _FILTERS_CORE_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/filters/filters_core.h
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

#include <linux/types.h>

struct task_struct;

typedef int (*tf_init)(void *data, size_t size);
typedef void (*tf_uninit)(void);
typedef struct task_struct *(*tf_call)(struct task_struct *task);

struct task_filter {
	tf_init init;
	tf_uninit uninit;
	tf_call call;
};

int register_filter(const char *name, struct task_filter *tf);
void unregister_filter(const char *name);


int init_filter(void *data, size_t size);
void uninit_filter(void);

int set_filter(const char *name);
struct task_struct *check_task(struct task_struct *task);

#endif /* _FILTERS_CORE_H */
