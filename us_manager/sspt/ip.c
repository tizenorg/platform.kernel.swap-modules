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
#include <linux/module.h>
#include "ip.h"
#include "sspt_page.h"
#include "sspt_file.h"
#include <us_manager/probes/use_probes.h>
#include <us_manager/img/img_ip.h>

/**
 * @brief Create us_ip struct
 *
 * @param page User page
 * @param offset Function offset from the beginning of the page
 * @param probe_i Pointer to the probe data.
 * @param page Pointer to the parent sspt_page struct
 * @return Pointer to the created us_ip struct
 */
struct us_ip *create_ip(struct img_ip *img_ip)
{
	struct us_ip *ip;

	ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	if (!ip)
		return NULL;

	memset(ip, 0, sizeof(*ip));
	INIT_LIST_HEAD(&ip->list);
	INIT_LIST_HEAD(&ip->img_list);
	ip->offset = img_ip->addr;
	ip->desc = &img_ip->desc;
	ip->iip = img_ip;
	list_add(&ip->img_list, &img_ip->ihead);

	return ip;
}

/**
 * @brief Remove us_ip struct
 *
 * @param ip remove object
 * @return Void
 */
void free_ip(struct us_ip *ip)
{
	if (!list_empty(&ip->img_list))
		list_del(&ip->img_list);

	kfree(ip);
}
