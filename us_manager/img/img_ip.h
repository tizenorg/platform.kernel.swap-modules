/**
 * @file us_manager/img/img_ip.h
 * @author Vyacheslav Cherkashin <v.cherkashin@samsung.com>
 *
 * @section LICENSE
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
 * @section COPYRIGHT
 * Copyright (C) Samsung Electronics, 2013
 *
 */


#ifndef _IMG_IP_H
#define _IMG_IP_H

#include <linux/types.h>
#include <us_manager/probes/probes.h>

/**
 * @struct img_ip
 * @breaf Image of instrumentation pointer
 */
struct img_ip {
	struct list_head list;		/**< For img_file */
	unsigned long addr;		/**< Function address */
	struct list_head ihead;		/**< List head for sspt ip */
	struct probe_desc *desc;	/**< Probe info */
};

struct img_ip *create_img_ip(unsigned long addr, struct probe_desc *info);
void free_img_ip(struct img_ip *ip);

/* debug */
void img_ip_print(struct img_ip *ip);
/* debug */

#endif /* _IMG_IP_H */
