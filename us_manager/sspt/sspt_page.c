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
#include "sspt_ip.h"
#include <us_manager/probes/use_probes.h>
#include <linux/slab.h>
#include <linux/list.h>

/**
 * @brief Create sspt_page struct
 *
 * @param offset File ofset
 * @return Pointer to the created sspt_page struct
 */
struct sspt_page *sspt_page_create(unsigned long offset)
{
	struct sspt_page *obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (obj) {
		INIT_HLIST_NODE(&obj->hlist);
		mutex_init(&obj->ip_list.mtx);
		INIT_LIST_HEAD(&obj->ip_list.inst);
		INIT_LIST_HEAD(&obj->ip_list.not_inst);
		obj->offset = offset;
		obj->file = NULL;
	}

	return obj;
}

/**
 * @brief Remove sspt_page struct
 *
 * @param page remove object
 * @return Void
 */
void sspt_page_free(struct sspt_page *page)
{
	struct sspt_ip *ip, *n;

	list_for_each_entry_safe(ip, n, &page->ip_list.inst, list) {
		list_del(&ip->list);
		sspt_ip_free(ip);
	}

	list_for_each_entry_safe(ip, n, &page->ip_list.not_inst, list) {
		list_del(&ip->list);
		sspt_ip_free(ip);
	}

	kfree(page);
}

static void sspt_list_add_ip(struct sspt_page *page, struct sspt_ip *ip)
{
	list_add(&ip->list, &page->ip_list.not_inst);
}

static void sspt_list_del_ip(struct sspt_ip *ip)
{
	list_del(&ip->list);
}

/**
 * @brief Add instruction pointer to sspt_page
 *
 * @param page Pointer to the sspt_page struct
 * @param ip Pointer to the us_ip struct
 * @return Void
 */
void sspt_add_ip(struct sspt_page *page, struct sspt_ip *ip)
{
	ip->offset &= ~PAGE_MASK;
	ip->page = page;
	sspt_list_add_ip(page, ip);
}

/**
 * @brief Del instruction pointer from sspt_page
 *
 * @param ip Pointer to the us_ip struct
 * @return Void
 */
void sspt_del_ip(struct sspt_ip *ip)
{
	sspt_list_del_ip(ip);
	sspt_ip_free(ip);
}

/**
 * @brief Check if probes are set on the page
 *
 * @param page Pointer to the sspt_page struct
 * @return Boolean
 */
bool sspt_page_is_installed(struct sspt_page *page)
{
	return !list_empty(&page->ip_list.inst);
}

/**
 * @brief Install probes on the page
 *
 * @param page Pointer to the sspt_page struct
 * @param file Pointer to the sspt_file struct
 * @return Error code
 */
int sspt_register_page(struct sspt_page *page, struct sspt_file *file)
{
	int err = 0;
	struct sspt_ip *ip, *n;

	mutex_lock(&page->ip_list.mtx);
	if (list_empty(&page->ip_list.not_inst)) {
		struct task_struct *task = page->file->proc->leader;

		printk(KERN_INFO "page %lx in %s task[tgid=%u, pid=%u] "
		       "already installed\n",
		       page->offset, file->dentry->d_iname,
		       task->tgid, task->pid);
		goto unlock;
	}

	list_for_each_entry_safe(ip, n, &page->ip_list.not_inst, list) {
		/* set virtual address */
		ip->orig_addr = file->vm_start + page->offset + ip->offset;

		err = sspt_register_usprobe(ip);
		if (err) {
			list_del(&ip->list);
			sspt_ip_free(ip);
			continue;
		}
	}

	list_splice_init(&page->ip_list.not_inst, &page->ip_list.inst);

unlock:
	mutex_unlock(&page->ip_list.mtx);

	return 0;
}

/**
 * @brief Uninstall probes on the page
 *
 * @param page Pointer to the sspt_page struct
 * @param flag Action for probes
 * @param task Pointer to the task_struct struct
 * @return Error code
 */
int sspt_unregister_page(struct sspt_page *page,
			 enum US_FLAGS flag,
			 struct task_struct *task)
{
	int err = 0;
	struct sspt_ip *ip;

	mutex_lock(&page->ip_list.mtx);
	if (list_empty(&page->ip_list.inst))
		goto unlock;

	list_for_each_entry(ip, &page->ip_list.inst, list) {
		err = sspt_unregister_usprobe(task, ip, flag);
		if (err != 0) {
			WARN_ON(1);
			break;
		}
	}

	if (flag != US_DISARM)
		list_splice_init(&page->ip_list.inst, &page->ip_list.not_inst);

unlock:
	mutex_unlock(&page->ip_list.mtx);
	return err;
}

void sspt_page_on_each_ip(struct sspt_page *page,
			  void (*func)(struct sspt_ip *, void *), void *data)
{
	struct sspt_ip *ip;

	mutex_lock(&page->ip_list.mtx);
	list_for_each_entry(ip, &page->ip_list.inst, list)
		func(ip, data);
	mutex_unlock(&page->ip_list.mtx);
}
