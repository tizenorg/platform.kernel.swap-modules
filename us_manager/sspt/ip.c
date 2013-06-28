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

#include <linux/slab.h>
#include "ip.h"
#include "sspt_page.h"
#include "sspt_file.h"

/* FIXME: */
#include "../../driver/us_def_handler.h"

struct us_ip *create_ip(unsigned long offset, const char *args)
{
	struct us_ip *ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	memset(ip, 0, sizeof(*ip));

	INIT_LIST_HEAD(&ip->list);
	ip->offset = offset;

	ip->got_addr = 0;
	ip->flag_got = 1;

	/* jprobe */
	ip->jprobe.pre_entry = ujprobe_event_pre_handler;
	ip->jprobe.entry = ujprobe_event_handler;

	/* TODO: or copy args?! */
	ip->jprobe.args = args;

	/* retprobe */
	ip->flag_retprobe = 1;
	ip->retprobe.handler = uretprobe_event_handler;

	return ip;
}

void free_ip(struct us_ip *ip)
{
	kfree(ip);
}
