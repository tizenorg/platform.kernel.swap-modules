#ifndef __SSPT_FILE__
#define __SSPT_FILE__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_file.h
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
#include <linux/types.h>

struct vm_area_struct;

struct sspt_file {
	struct list_head list;			// for proc_probes
	struct sspt_proc *proc;
	struct dentry *dentry;
	int loaded;
	unsigned long vm_start;
	unsigned long vm_end;

	unsigned long page_probes_hash_bits;
	struct hlist_head *page_probes_table; // for page_probes
};


struct sspt_file *sspt_file_create(struct dentry *dentry, int page_cnt);
void sspt_file_free(struct sspt_file *file);

struct sspt_page *sspt_find_page_mapped(struct sspt_file *file, unsigned long page);
void sspt_file_add_ip(struct sspt_file *file, struct ip_data *ip_d);

struct sspt_page *sspt_get_page(struct sspt_file *file, unsigned long offset_addr);
void sspt_put_page(struct sspt_page *page);

int sspt_file_check_install_pages(struct sspt_file *file);
void sspt_file_install(struct sspt_file *file);
int sspt_file_uninstall(struct sspt_file *file, struct task_struct *task, enum US_FLAGS flag);
void sspt_file_set_mapping(struct sspt_file *file, struct vm_area_struct *vma);

#endif /* __SSPT_FILE__ */
