#ifndef __IP__
#define __IP__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/ip.h
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

#include <linux/list.h>
#include "../../kprobe/dbi_kprobes.h"

// TODO: tmp struct ip_data
struct ip_data {
	unsigned long offset;
	unsigned long got_addr;

	kprobe_pre_entry_handler_t pre_handler;
	unsigned long jp_handler;
	kretprobe_handler_t rp_handler;

	unsigned flag_retprobe:1;
};

struct sspt_page;
struct sspt_file;

struct us_ip {
	struct list_head list;

	struct jprobe jprobe;
	struct kretprobe retprobe;

	unsigned long offset;
	unsigned long got_addr;

	unsigned flag_retprobe:1;
	unsigned flag_got:1;
};


struct us_ip *create_ip(unsigned long offset);
struct us_ip *copy_ip(const struct us_ip *ip);
struct us_ip *create_ip_by_ip_data(struct ip_data *ip_d);
void free_ip(struct us_ip *ip);

void sspt_set_ip_addr(struct us_ip *ip, const struct sspt_page *page, const struct sspt_file *file);

#endif /* __IP__ */
