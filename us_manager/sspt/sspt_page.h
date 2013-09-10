#ifndef __SSPT_PAGE__
#define __SSPT_PAGE__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_page.h
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
#include <linux/spinlock.h>

struct us_ip;
struct sspt_file;
struct task_struct;
enum US_FLAGS;

struct sspt_page {
	struct list_head ip_list_inst;
	struct list_head ip_list_no_inst;
	unsigned long offset;
	spinlock_t lock;

	struct sspt_file *file;
	struct hlist_node hlist; // for file_probes
};

struct sspt_page *sspt_page_create(unsigned long offset);
void sspt_page_free(struct sspt_page *page);

void sspt_add_ip(struct sspt_page *page, struct us_ip *ip);
void sspt_del_ip(struct us_ip *ip);

int sspt_page_is_installed(struct sspt_page *page);

int sspt_register_page(struct sspt_page *page, struct sspt_file *file);

int sspt_unregister_page(struct sspt_page *page,
			 enum US_FLAGS flag,
			 struct task_struct *task);

#endif /* __SSPT_PAGE__ */
