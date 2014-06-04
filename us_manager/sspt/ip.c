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


/**
 * @brief Create us_ip struct
 *
 * @param offset Function offset from the beginning of the page
 * @param probe_i Pointer to the probe data.
 * @return Pointer to the created us_ip struct
 */
struct us_ip *create_ip(unsigned long offset, const struct probe_info *probe_i)
{
	size_t len = probe_i->size;
	struct us_ip *ip;

	ip = kmalloc(sizeof(*ip) + len, GFP_ATOMIC);
	if (ip != NULL) {
		memset(ip, 0, sizeof(*ip) + len);

		INIT_LIST_HEAD(&ip->list);
		ip->offset = offset;

		probe_info_copy(probe_i, &ip->probe_i);
		probe_info_init(&ip->probe_i, ip);
	} else {
		printk("Cannot kmalloc in create_ip function!\n");
	}

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
	probe_info_uninit(&ip->probe_i, ip);
	kfree(ip);
}
