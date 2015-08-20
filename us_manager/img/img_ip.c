/*
 *  SWAP uprobe manager
 *  modules/us_manager/img/img_ip.c
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


#include "img_ip.h"
#include <us_manager/probes/use_probes.h>
#include <us_manager/sspt/ip.h>
#include <linux/slab.h>

/**
 * @brief Create img_ip struct
 *
 * @param addr Function address
 * @param probe_i Pointer to the probe info data.
 * @return Pointer to the created img_ip struct
 */
struct img_ip *create_img_ip(unsigned long addr, struct probe_desc *pd)
{
	struct img_ip *ip;

	ip = kmalloc(sizeof(*ip), GFP_KERNEL);
	if (!ip)
		return NULL;

	INIT_LIST_HEAD(&ip->list);
	INIT_LIST_HEAD(&ip->ihead);
	ip->addr = addr;
	ip->desc = pd;

	return ip;
}

/**
 * @brief Remove img_ip struct
 *
 * @param ip remove object
 * @return Void
 */
void free_img_ip(struct img_ip *ip)
{
	struct us_ip *p, *n;

	list_for_each_entry_safe(p, n, &ip->ihead, img_list) {
		list_del_init(&p->img_list);
		p->iip = NULL;
		list_del(&p->list);
		probe_info_unregister(p->desc->type, p, 1);
		free_ip(p);
	}

	kfree(ip);
}

/**
 * @brief For debug
 *
 * @param ip Pointer to the img_ip struct
 * @return Void
 */

/* debug */
void img_ip_print(struct img_ip *ip)
{
	if (ip->desc->type == SWAP_RETPROBE)
		printk(KERN_INFO "###            addr=8%lx, args=%s\n",
		       ip->addr, ip->desc->info.rp_i.args);
}
/* debug */
