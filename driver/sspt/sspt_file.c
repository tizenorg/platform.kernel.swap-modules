/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_file.c
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

#include "sspt_file.h"
#include "sspt_page.h"
#include "sspt_procs.h"
#include <storage.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <dbi_kprobes_deps.h>

static int calculation_hash_bits(int cnt)
{
	int bits;
	for (bits = 1; cnt >>= 1; ++bits);

	return bits;
}

struct sspt_file *sspt_file_create(char *name, struct dentry *dentry, int page_cnt)
{
	struct sspt_file *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);

	if (obj) {
		int i, table_size;
		INIT_LIST_HEAD(&obj->list);
		obj->procs = NULL;
		obj->name = name;
		obj->dentry = dentry;
		obj->loaded = 0;
		obj->vm_start = 0;
		obj->vm_end = 0;

		obj->page_probes_hash_bits = calculation_hash_bits(page_cnt);//PAGE_PROBES_HASH_BITS;
		table_size = (1 << obj->page_probes_hash_bits);

		obj->page_probes_table = kmalloc(sizeof(*obj->page_probes_table)*table_size, GFP_ATOMIC);

		for (i = 0; i < table_size; ++i) {
			INIT_HLIST_HEAD(&obj->page_probes_table[i]);
		}
	}

	return obj;
}

void sspt_file_free(struct sspt_file *file)
{
	struct hlist_node *p, *n;
	struct hlist_head *head;
	struct sspt_page *page;
	int i, table_size = (1 << file->page_probes_hash_bits);

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		swap_hlist_for_each_entry_safe(page, p, n, head, hlist) {
			hlist_del(&page->hlist);
			sspt_page_free(page);
		}
	}

	kfree(file->page_probes_table);
	kfree(file);
}

static void sspt_add_page(struct sspt_file *file, struct sspt_page *page)
{
	page->file = file;
	hlist_add_head(&page->hlist, &file->page_probes_table[hash_ptr((void *)page->offset,
				file->page_probes_hash_bits)]);
}

struct sspt_file *sspt_file_copy(const struct sspt_file *file)
{
	struct sspt_file *file_out;

	if (file == NULL) {
		printk("### WARNING: file_p == NULL\n");
		return NULL;
	}

	file_out = kmalloc(sizeof(*file_out), GFP_ATOMIC);
	if (file_out) {
		struct sspt_page *page = NULL;
		struct hlist_node *node = NULL;
		struct hlist_head *head = NULL;
		int i, table_size;
		INIT_LIST_HEAD(&file_out->list);
		file_out->procs = NULL;
		file_out->dentry = file->dentry;
		file_out->name = file->name;
		file_out->loaded = 0;
		file_out->vm_start = 0;
		file_out->vm_end = 0;

		file_out->page_probes_hash_bits = file->page_probes_hash_bits;
		table_size = (1 << file_out->page_probes_hash_bits);

		file_out->page_probes_table =
				kmalloc(sizeof(*file_out->page_probes_table)*table_size, GFP_ATOMIC);

		for (i = 0; i < table_size; ++i) {
			INIT_HLIST_HEAD(&file_out->page_probes_table[i]);
		}

		// copy pages
		for (i = 0; i < table_size; ++i) {
			head = &file->page_probes_table[i];
			swap_hlist_for_each_entry(page, node, head, hlist) {
				sspt_add_page(file_out, sspt_page_copy(page));
			}
		}
	}

	return file_out;
}

static struct sspt_page *sspt_find_page(struct sspt_file *file, unsigned long offset)
{
	struct hlist_node *node;
	struct hlist_head *head;
	struct sspt_page *page;

	head = &file->page_probes_table[hash_ptr((void *)offset, file->page_probes_hash_bits)];
	swap_hlist_for_each_entry(page, node, head, hlist) {
		if (page->offset == offset) {
			return page;
		}
	}

	return NULL;
}

static struct sspt_page *sspt_find_page_or_new(struct sspt_file *file, unsigned long offset)
{
	struct sspt_page *page = sspt_find_page(file, offset);

	if (page == NULL) {
		page = sspt_page_create(offset);
		sspt_add_page(file, page);
	}

	return page;
}

struct sspt_page *sspt_find_page_mapped(struct sspt_file *file, unsigned long page)
{
	unsigned long offset;

	if (file->vm_start > page || file->vm_end < page) {
		// TODO: or panic?!
		printk("ERROR: file_p[vm_start..vm_end] <> page: file_p[vm_start=%lx, vm_end=%lx, path=%s, d_iname=%s] page=%lx\n",
				file->vm_start, file->vm_end, file->name, file->dentry->d_iname, page);
		return NULL;
	}

	offset = page - file->vm_start;

	return sspt_find_page(file, offset);
}

void sspt_file_add_ip(struct sspt_file *file, struct ip_data *ip_d)
{
	unsigned long offset = ip_d->offset & PAGE_MASK;
	struct sspt_page *page = sspt_find_page_or_new(file, offset);

	// FIXME: delete ip
	struct us_ip *ip = create_ip_by_ip_data(ip_d);

	sspt_add_ip(page, ip);
}

struct sspt_page *sspt_get_page(struct sspt_file *file, unsigned long offset_addr)
{
	unsigned long offset = offset_addr & PAGE_MASK;
	struct sspt_page *page = sspt_find_page_or_new(file, offset);

	spin_lock(&page->lock);

	return page;
}

void sspt_put_page(struct sspt_page *page)
{
	spin_unlock(&page->lock);
}

int sspt_file_check_install_pages(struct sspt_file *file)
{
	int i, table_size;
	struct sspt_page *page;
	struct hlist_node *node, *tmp;
	struct hlist_head *head;

	table_size = (1 << file->page_probes_hash_bits);
	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		swap_hlist_for_each_entry_safe(page, node, tmp, head, hlist) {
			if (sspt_page_is_install(page)) {
				return 1;
			}
		}
	}

	return 0;
}

void sspt_file_install(struct sspt_file *file)
{
	struct sspt_page *page = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;
	int i, table_size = (1 << file->page_probes_hash_bits);

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		swap_hlist_for_each_entry_rcu(page, node, head, hlist) {
			sspt_register_page(page, file);
		}
	}
}

void sspt_file_set_mapping(struct sspt_file *file, struct vm_area_struct *vma)
{
	struct task_struct *task = file->procs->task;
	int app_flag = (vma->vm_file->f_dentry == file->procs->dentry);

	file->vm_start = vma->vm_start;
	file->vm_end = vma->vm_end;

	pack_event_info(DYN_LIB_PROBE_ID, RECORD_ENTRY, "dspdd",
			task->tgid, file->name, vma->vm_start,
			vma->vm_end - vma->vm_start, app_flag);
}
