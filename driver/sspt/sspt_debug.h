#ifndef __SSPT_DEBUG__
#define __SSPT_DEBUG__

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/driver/sspt/sspt_debug.h
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

static void print_jprobe(struct jprobe *jp)
{
	printk("###         JP: entry=%x, pre_entry=%x\n",
			jp->entry, jp->pre_entry);
}

static void print_retprobe(struct kretprobe *rp)
{
	printk("###         RP: handler=%x\n",
			rp->handler);
}

static void print_page_probes(const struct sspt_page *page)
{
	int i = 0;
	struct us_ip *ip;

	printk("###     offset=%x\n", page->offset);
	list_for_each_entry(ip, &page->ip_list, list) {

		printk("###       addr[%2d]=%x, J_addr=%x, R_addr=%x\n",
				i, ip->offset, ip->jprobe.kp.addr, ip->retprobe.kp.addr);
		print_jprobe(&ip->jprobe);
		print_retprobe(&ip->retprobe);
		++i;
	}
}

static void print_file_probes(const struct sspt_file *file)
{
	int i, table_size;
	struct sspt_page *page = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;
	static const char *NA = "N/A";

	if (file == NULL) {
		printk("### file_p == NULL\n");
		return;
	}

	table_size = (1 << file->page_probes_hash_bits);
	const char *name = (file->dentry) ? file->dentry->d_iname : NA;

	printk("### print_file_probes: path=%s, d_iname=%s, table_size=%d, vm_start=%x\n",
			file->path, name, table_size, file->vm_start);

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		hlist_for_each_entry_rcu(page, node, head, hlist) {
			print_page_probes(page);
		}
	}
}

static void print_proc_probes(const struct sspt_procs *procs)
{
	struct sspt_file *file;

	printk("### print_proc_probes\n");
	list_for_each_entry(file, &procs->file_list, list) {
		print_file_probes(file);
	}
	printk("### print_proc_probes\n");
}

void print_inst_us_proc(const inst_us_proc_t *task_inst_info)
{
	int i;
	int cnt = task_inst_info->libs_count;
	printk(  "### BUNDLE PRINT START ###\n");
	printk("\n### BUNDLE PRINT START ###\n");
	printk("### task_inst_info.libs_count=%d\n", cnt);

	for (i = 0; i < cnt; ++i) {
		int j;

		us_proc_lib_t *lib = &task_inst_info->p_libs[i];
		int cnt_j = lib->ips_count;
		char *path = lib->path;
		printk("###     path=%s, cnt_j=%d\n", path, cnt_j);

		for (j = 0; j < cnt_j; ++j) {
			struct us_ip *ips = &lib->p_ips[j];
			unsigned long offset = ips->offset;
			printk("###         offset=%x\n", offset);
		}
	}
	printk("### BUNDLE PRINT  END  ###\n");
}

#endif /* __SSPT_DEBUG__ */
