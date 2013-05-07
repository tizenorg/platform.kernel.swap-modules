/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_page.c
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

#include "sspt.h"
#include "sspt_page.h"
#include "sspt_file.h"
#include "ip.h"
#include <linux/slab.h>
#include <linux/list.h>

struct sspt_page *sspt_page_create(unsigned long offset)
{
	struct sspt_page *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);
	if (obj) {
		INIT_LIST_HEAD(&obj->ip_list);
		obj->offset = offset;
		obj->install = 0;
		spin_lock_init(&obj->lock);
		obj->file = NULL;
		INIT_HLIST_NODE(&obj->hlist);
	}

	return obj;
}

void sspt_page_free(struct sspt_page *page)
{
	struct us_ip *ip, *n;

	list_for_each_entry_safe(ip, n, &page->ip_list, list) {
		list_del(&ip->list);
		free_ip(ip);
	}

	kfree(page);
}

static void sspt_list_add_ip(struct sspt_page *page, struct us_ip *ip)
{
	list_add(&ip->list, &page->ip_list);
	ip->page = page;
}

struct sspt_page *sspt_page_copy(const struct sspt_page *page)
{
	struct us_ip *ip, *new_ip;
	struct sspt_page *new_page = kmalloc(sizeof(*new_page), GFP_ATOMIC);

	if (new_page) {
		INIT_LIST_HEAD(&new_page->ip_list);
		list_for_each_entry(ip, &page->ip_list, list) {
			new_ip = copy_ip(ip);
			if (new_ip == NULL) {
				sspt_page_free(new_page);
				return NULL;
			}

			sspt_list_add_ip(new_page, new_ip);
		}

		new_page->offset = page->offset;
		new_page->install = 0;
		spin_lock_init(&new_page->lock);
		INIT_HLIST_NODE(&new_page->hlist);
		new_page->file = NULL;
	}

	return new_page;
}

void sspt_add_ip(struct sspt_page *page, struct us_ip *ip)
{
	struct us_ip *ip_tmp;

	ip->offset &= ~PAGE_MASK;

	list_for_each_entry(ip_tmp, &page->ip_list, list) {
		if (ip_tmp->offset == ip->offset) {
			/* TODO: process second instanse of probe */
			return;
		}
	}

	sspt_list_add_ip(page, ip);
}

struct us_ip *sspt_find_ip(struct sspt_page *page, unsigned long offset)
{
	struct us_ip *ip;

	list_for_each_entry(ip, &page->ip_list, list) {
		if (ip->offset == offset) {
			return ip;
		}
	}

	return NULL;
}

void sspt_set_all_ip_addr(struct sspt_page *page, const struct sspt_file *file)
{
	struct us_ip *ip;
	unsigned long addr;

	list_for_each_entry(ip, &page->ip_list, list) {
		addr = file->vm_start + page->offset + ip->offset;
		ip->retprobe.up.kp.addr = ip->jprobe.up.kp.addr = (kprobe_opcode_t *)addr;
	}
}

int sspt_register_page(struct sspt_page *page,
		       struct sspt_file *file,
		       struct task_struct *task)
{
	int err = 0;
	struct us_ip *ip, *n;

	spin_lock(&page->lock);

	if (sspt_page_is_install(page)) {
		printk("page %lx in %s task[tgid=%u, pid=%u] already installed\n",
				page->offset, file->dentry->d_iname, task->tgid, task->pid);
		goto unlock;
	}

	sspt_page_assert_install(page);
	sspt_set_all_ip_addr(page, file);

	list_for_each_entry_safe(ip, n, &page->ip_list, list) {
		err = sspt_register_usprobe(task, ip);
		if (err == -ENOEXEC) {
			list_del(&ip->list);
			free_ip(ip);
			continue;
		} else if (err) {
			printk("Failed to install probe\n");
		}
	}
unlock:
	sspt_page_installed(page);
	spin_unlock(&page->lock);

	return 0;
}

int sspt_unregister_page(struct sspt_page *page,
			 enum US_FLAGS flag,
			 struct task_struct *task)
{
	int err = 0;
	struct us_ip *ip;

	spin_lock(&page->lock);
	if (!sspt_page_is_install(page)) {
		spin_unlock(&page->lock);
		return 0;
	}

	list_for_each_entry(ip, &page->ip_list, list) {
		err = sspt_unregister_usprobe(task, ip, flag);
		if (err != 0) {
			//TODO: ERROR
			break;
		}
	}

	if (flag != US_DISARM) {
		sspt_page_uninstalled(page);
	}
	spin_unlock(&page->lock);

	return err;
}
