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

struct sspt_page {
	struct list_head ip_list;
	unsigned long offset;
	int install;
	spinlock_t lock;

	struct hlist_node hlist; // for file_probes
};

struct sspt_page *sspt_page_create(unsigned long offset);
struct sspt_page *sspt_page_copy(const struct sspt_page *page);
void sspt_page_free(struct sspt_page *page);

void sspt_add_ip(struct sspt_page *page, struct us_ip *ip);
struct us_ip *sspt_find_ip(struct sspt_page *page, unsigned long offset);

static inline void sspt_page_assert_install(const struct sspt_page *page)
{
	if (page->install != 0) {
		panic("already installed page %lx\n", page->offset);
	}
}

static inline int sspt_page_is_install(struct sspt_page *page)
{
	return page->install;
}

static inline void sspt_page_installed(struct sspt_page *page)
{
	page->install = 1;
}

static inline void sspt_page_uninstalled(struct sspt_page *page)
{
	page->install = 0;
}

void sspt_set_all_ip_addr(struct sspt_page *page, const struct sspt_file *file);

#endif /* __SSPT_PAGE__ */
