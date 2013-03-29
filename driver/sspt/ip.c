/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/ip.c
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

#include "ip.h"
#include "sspt_page.h"
#include "sspt_file.h"

struct us_ip *create_ip(unsigned long offset)
{
	struct us_ip *ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	memset(ip, 0, sizeof(*ip));

	INIT_LIST_HEAD(&ip->list);
	ip->offset = offset;

	return ip;
}

void free_ip(struct us_ip *ip)
{
	kfree(ip);
}

static inline void set_ip_jp_handler(struct us_ip *ip, kprobe_pre_entry_handler_t per_entry, void *entry)
{
	ip->jprobe.pre_entry = per_entry;
	ip->jprobe.entry = entry;
}

static inline void set_ip_rp_handler(struct us_ip *ip, uretprobe_handler_t handler)
{
	ip->flag_retprobe = 1;
	ip->retprobe.handler = handler;
}

static inline void set_ip_got_addr(struct us_ip *ip, unsigned long got_addr)
{
	ip->got_addr = got_addr;
}

struct us_ip *copy_ip(const struct us_ip *ip)
{
	struct us_ip *new_ip = create_ip(ip->offset);

	if (new_ip == NULL) {
		printk("us_proc_ip_copy: No enough memory\n");
		return NULL;
	}

	// jprobe
	set_ip_jp_handler(new_ip, ip->jprobe.pre_entry, ip->jprobe.entry);

	// retprobe
	if (ip->flag_retprobe) {
		set_ip_rp_handler(new_ip, ip->retprobe.handler);
	}

	return new_ip;
}

struct us_ip *create_ip_by_ip_data(struct ip_data *ip_d)
{
	struct us_ip *ip = create_ip(ip_d->offset);
	set_ip_jp_handler(ip, ip_d->pre_handler, (void *)ip_d->jp_handler);

	if (ip_d->flag_retprobe) {
		set_ip_rp_handler(ip, ip_d->rp_handler);
	}

	set_ip_got_addr(ip, ip_d->got_addr);

	return ip;
}

void sspt_set_ip_addr(struct us_ip *ip, const struct sspt_page *page, const struct sspt_file *file)
{
	unsigned long addr = file->vm_start + page->offset + ip->offset;
	ip->retprobe.up.kp.addr = ip->jprobe.up.kp.addr = (kprobe_opcode_t *)addr;
}
