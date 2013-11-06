/*
 *  SWAP uprobe manager
 *  modules/us_manager/img/img_file.h
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


#ifndef _IMG_FILE_H
#define _IMG_FILE_H

#include <linux/types.h>

struct img_file {
	struct list_head list;			/* for img_proc */
	struct dentry *dentry;
	struct list_head ip_list;		/* for img_ip */
};

struct img_file *create_img_file(struct dentry *dentry);
void free_img_file(struct img_file *ip);

int img_file_add_ip(struct img_file *file, unsigned long addr,
		    const char *args, char ret_type);
int img_file_del_ip(struct img_file *file, unsigned long addr);

int img_file_empty(struct img_file *file);

/* debug */
void img_file_print(struct img_file *file);
/* debug */

#endif /* _IMG_FILE_H */

