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
#include <writer/swap_writer_module.h>
#include <us_manager/us_manager.h>


static int entry_handler(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct uretprobe *rp = ri->rp;

	if (rp && get_quiet() == QT_OFF) {
		struct us_ip *ip = container_of(rp, struct us_ip, retprobe);

		entry_event(ip->args, regs, PT_US, PST_NONE);
	}

	return 0;
}

static int ret_handler(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct uretprobe *rp = ri->rp;

	if (rp && get_quiet() == QT_OFF) {
		struct us_ip *ip = container_of(rp, struct us_ip, retprobe);
		unsigned long addr = (unsigned long)ip->retprobe.up.kp.addr;
		unsigned long ret_addr = ri->ret_addr;

#if defined(CONFIG_ARM)
		addr = ip->offset & 0x01 ? addr | 0x01 : addr;
#endif

		exit_event(regs, addr, ret_addr);
	}

	return 0;
}

struct us_ip *create_ip(unsigned long offset, const char *args)
{
	struct us_ip *ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	memset(ip, 0, sizeof(*ip));

	INIT_LIST_HEAD(&ip->list);
	ip->offset = offset;

	/* TODO: or copy args?! */
	ip->args = args;

	/* retprobe */
	ip->retprobe.handler = ret_handler;
	ip->retprobe.entry_handler = entry_handler;

	return ip;
}

void free_ip(struct us_ip *ip)
{
	kfree(ip);
}
