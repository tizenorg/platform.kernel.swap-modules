/*
 *  SWAP uprobe manager
 *  modules/us_manager/img_proc.h
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


#ifndef _IMG_PROC_H
#define _IMG_PROC_H

#include <linux/types.h>

struct dentry;

struct img_proc {
	struct list_head file_list;
};

struct img_proc *create_img_proc(void);
void free_img_proc(struct img_proc *proc);

int img_proc_add_ip(struct img_proc *proc, struct dentry *dentry,
		    unsigned long addr, const char *args, char ret_type);
int img_proc_del_ip(struct img_proc *proc, struct dentry *dentry, unsigned long addr);

/* debug */
void img_proc_print(struct img_proc *proc);
/* debug */

#endif /* _IMG_PROC_H */
