#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/hash.h>
#include "storage.h"

enum US_FLAGS {
	US_UNREGS_PROBE,
	US_NOT_RP2,
	US_DISARM
};

struct page_probes {
	struct list_head ip_list;
	unsigned long offset;
	int install;
	spinlock_t lock;

	struct hlist_node hlist; // for file_probes
};

struct file_probes {
	struct dentry *dentry;
	char *path;
	int loaded;
	unsigned long vm_start;
	unsigned long vm_end;

	unsigned long page_probes_hash_bits;
	struct hlist_head *page_probes_table; // for page_probes
};

struct proc_probes {
	struct dentry *dentry;
	size_t cnt;
	struct file_probes **file_p;
};

us_proc_ip_t *us_proc_ip_copy(const us_proc_ip_t *ip)
{
	us_proc_ip_t *ip_out = kmalloc(sizeof(*ip_out), GFP_ATOMIC);
	if (ip_out == NULL) {
		DPRINTF ("us_proc_ip_copy: No enough memory");
		return NULL;
	}

	memcpy (ip_out, ip, sizeof(*ip_out));

	ip_out->installed = 0;
	memset(&ip_out->jprobe, 0, sizeof(struct jprobe));
	memset(&ip_out->retprobe, 0, sizeof(struct kretprobe));

	ip_out->jprobe.entry = ip->jprobe.entry;
	ip_out->jprobe.pre_entry = ip->jprobe.pre_entry;
	ip_out->retprobe.handler = ip->retprobe.handler;

	INIT_LIST_HEAD(&ip_out->list);

	return ip_out;
}

us_proc_ip_t *us_proc_ips_copy(const us_proc_ip_t *ips, int cnt)
{
	int i;
	kprobe_opcode_t *entry_save;
	kprobe_pre_entry_handler_t pre_entry_save;
	kretprobe_handler_t handler_save;

	us_proc_ip_t *ips_out =
		kmalloc (cnt * sizeof (us_proc_ip_t), GFP_ATOMIC);

	if (!ips_out) {
		DPRINTF ("No enough memory for copy_info->p_libs[i].p_ips");
		return NULL;
	}

	memcpy (ips_out, ips, cnt * sizeof (us_proc_ip_t));
	for (i = 0; i < cnt; ++i) {
		// save handlers
		entry_save = ips_out[i].jprobe.entry;
		pre_entry_save = ips_out[i].jprobe.pre_entry;
		handler_save = ips_out[i].retprobe.handler;

		ips_out[i].installed = 0;
		memset(&ips_out[i].jprobe, 0, sizeof(struct jprobe));
		memset(&ips_out[i].retprobe, 0, sizeof(struct kretprobe));

		// restore handlers
		ips_out[i].jprobe.entry = entry_save;
		ips_out[i].jprobe.pre_entry = pre_entry_save;
		ips_out[i].retprobe.handler = handler_save;
	}

	return ips_out;
}

// page_probes
static struct page_probes *page_p_new(unsigned long offset)
{
	struct page_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);
	if (obj) {
		INIT_LIST_HEAD(&obj->ip_list);
		obj->offset = offset;
		obj->install = 0;
		spin_lock_init(&obj->lock);
		INIT_HLIST_NODE(&obj->hlist);
	}

	return obj;
}

static void page_p_del(struct page_probes *page_p)
{
	// TODO: del
}

struct page_probes *page_p_copy(const struct page_probes *page_p)
{
	us_proc_ip_t *ip_in, *ip_out;
	struct page_probes *page_p_out = kmalloc(sizeof(*page_p), GFP_ATOMIC);

	if (page_p_out) {
		INIT_LIST_HEAD(&page_p_out->ip_list);
		list_for_each_entry(ip_in, &page_p->ip_list, list) {
			ip_out = us_proc_ip_copy(ip_in);
			if (ip_out == NULL) {
				// FIXME: free ip_list in page_p_out
				kfree(page_p_out);
				return NULL;
			}

			list_add(&ip_out->list, &page_p_out->ip_list);
		}

		page_p_out->offset = page_p->offset;
		page_p_out->install = 0;
		spin_lock_init(&page_p_out->lock);
		INIT_HLIST_NODE(&page_p_out->hlist);
	}

	return page_p_out;
}

void page_p_add_ip(struct page_probes *page_p, us_proc_ip_t *ip)
{
	ip->offset &= ~PAGE_MASK;
	INIT_LIST_HEAD(&ip->list);
	list_add(&ip->list, &page_p->ip_list);
}

static void page_p_assert_install(const struct page_probes *page_p)
{
	if (page_p->install != 0) {
		panic("already installed page %x\n", page_p->offset);
	}
}

static int page_p_is_install(struct page_probes *page_p)
{
	return page_p->install;
}

static void page_p_installed(struct page_probes *page_p)
{
	page_p->install = 1;
}

static void page_p_uninstalled(struct page_probes *page_p)
{
	page_p->install = 0;
}
// page_probes

static void page_p_set_all_kp_addr(struct page_probes *page_p, const struct file_probes *file_p)
{
	us_proc_ip_t *ip;
	unsigned long addr;

	list_for_each_entry(ip, &page_p->ip_list, list) {
		addr = file_p->vm_start + page_p->offset + ip->offset;
		ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
//		printk("###       pp_set_all_kp_addr: start=%x, page_offset=%x, ip_offset=%x, addr=%x\n",
//				file_p->vm_start, page_p->offset, ip->offset, addr);
	}
}

static int calculation_hash_bits(int cnt)
{
	int bits;
	for (bits = 1; cnt >>= 1; ++bits);

	return bits;
}

// file_probes
static struct file_probes *file_p_new(us_proc_lib_t *lib, int page_cnt)
{
	struct file_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);

	if (obj) {
		int i, table_size;
		obj->dentry = lib->m_f_dentry;
		obj->path = lib->path;
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

static void file_p_del(struct file_probes *file_p)
{
	// TODO: del
}

static void file_p_add_page_p(struct file_probes *file_p, struct page_probes *page_p)
{
	hlist_add_head_rcu(&page_p->hlist, &file_p->page_probes_table[hash_ptr(page_p->offset, file_p->page_probes_hash_bits)]);
}

static struct file_probes *file_p_copy(const struct file_probes *file_p)
{
	struct file_probes *file_p_out;

	if (file_p == NULL) {
		printk("### WARNING: file_p == NULL\n");
		return NULL;
	}

	file_p_out = kmalloc(sizeof(*file_p_out), GFP_ATOMIC);
	if (file_p_out) {
		struct page_probes *page_p = NULL;
		struct hlist_node *node = NULL;
		struct hlist_head *head = NULL;
		int i, table_size;
		file_p_out->dentry = file_p->dentry;
		file_p_out->path = file_p->path;
		file_p_out->loaded = 0;
		file_p_out->vm_start = 0;
		file_p_out->vm_end = 0;

		file_p_out->page_probes_hash_bits = file_p->page_probes_hash_bits;
		table_size = (1 << file_p_out->page_probes_hash_bits);

		file_p_out->page_probes_table =
				kmalloc(sizeof(*file_p_out->page_probes_table)*table_size, GFP_ATOMIC);

		for (i = 0; i < table_size; ++i) {
			INIT_HLIST_HEAD(&file_p_out->page_probes_table[i]);
		}

		// copy pages
		for (i = 0; i < table_size; ++i) {
			head = &file_p->page_probes_table[i];
			hlist_for_each_entry_rcu(page_p, node, head, hlist) {
				file_p_add_page_p(file_p_out, page_p_copy(page_p));
			}
		}
	}

	return file_p_out;
}

static struct page_probes *file_p_find_page_p(struct file_probes *file_p, unsigned long page)
{
	struct page_probes *page_p;
	struct hlist_node *node;
	struct hlist_head *head;
	unsigned long offset;

	if (file_p->vm_start > page || file_p->vm_end < page) {
		// TODO: or panic?!
		printk("ERROR: file_p[vm_start..vm_end] <> page: file_p[vm_start=%x, vm_end=%x, path=%s, d_iname=%s] page=%x\n",
				file_p->vm_start, file_p->vm_end, file_p->path, file_p->dentry->d_iname, page);
		return NULL;
	}

	offset = page - file_p->vm_start;

	head = &file_p->page_probes_table[hash_ptr(offset, file_p->page_probes_hash_bits)];
	hlist_for_each_entry_rcu(page_p, node, head, hlist) {
		if (page_p->offset == offset) {
			return page_p;
		}
	}

	return NULL;
}
// file_probes

#include "storage.h"

static void print_proc_probes(const struct proc_probes *proc_p);

struct proc_probes *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	const int tmp_hash_bits = 12;
	const int tmp_table_size = (1 << tmp_hash_bits);
	struct hlist_head *tmp_page_probes_table = kmalloc(tmp_table_size* sizeof(*tmp_page_probes_table), GFP_KERNEL);
	int tmp_i;

	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	printk("####### get START #######\n");

	if (proc_p) {
		int i;
		proc_p->cnt = task_inst_info->libs_count;
		proc_p->dentry = task_inst_info->m_f_dentry;
		proc_p->file_p = kmalloc(sizeof(*proc_p->file_p)*proc_p->cnt, GFP_ATOMIC);

		printk("#2# get_file_probes: proc_p[cnt=%d, dentry=%p, file_p=%p]\n",
				proc_p->cnt, proc_p->dentry, proc_p->file_p);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct file_probes *file_p = NULL;
			int k, page_cnt = 0;

			printk("#3# get_file_probes: p_libs[ips_count=%d, dentry=%p, %s %s\n",
					p_libs->ips_count, p_libs->m_f_dentry, p_libs->path, p_libs->path_dyn);
			if (p_libs->ips_count == 0) {
				proc_p->file_p[i] = NULL;
				continue;
			}

			// init tmp_page_probes_table
			for (tmp_i = 0; tmp_i < tmp_table_size; ++tmp_i) {
				INIT_HLIST_HEAD(&tmp_page_probes_table[tmp_i]);
			}

			// fill tmp_page_probes_table
			for (k = 0; k < p_libs->ips_count; ++k) {
				struct hlist_node *node;
				struct hlist_head *head;
				us_proc_ip_t *ip = &p_libs->p_ips[k];
				unsigned long offset = ip->offset & PAGE_MASK;
				struct page_probes *page_p_tmp, *page_p = NULL;

				head = &tmp_page_probes_table[hash_ptr(offset, tmp_hash_bits)];
				hlist_for_each_entry(page_p_tmp, node, head, hlist) {
					if (page_p_tmp->offset == offset) {
						page_p = page_p_tmp;
						break;
					}
				}

				if (page_p == NULL) {
					page_p = page_p_new(offset);
					hlist_add_head(&page_p->hlist, &tmp_page_probes_table[hash_ptr(page_p->offset, tmp_hash_bits)]);
				}

				page_p_add_ip(page_p, ip);
			}

			// calculation page_cnt
			page_cnt = 0;
			for (tmp_i = 0; tmp_i < tmp_table_size; ++tmp_i) {
				struct page_probes *page_p;
				struct hlist_node *node;
				struct hlist_head *head = &tmp_page_probes_table[tmp_i];
				hlist_for_each_entry(page_p, node, head, hlist) {
					++page_cnt;
				}
			}

			printk("#4# get_file_probes: page_cnt=%d\n", page_cnt);

			file_p = file_p_new(p_libs, page_cnt);

			// fill file_p
			for (tmp_i = 0; tmp_i < tmp_table_size; ++tmp_i) {
				struct page_probes *page_p;
				struct hlist_node *node, *n;
				struct hlist_head *head = &tmp_page_probes_table[tmp_i];
				hlist_for_each_entry_safe(page_p, node, n, head, hlist) {
					hlist_del_init(&page_p->hlist);
					file_p_add_page_p(file_p, page_p);
				}
			}

			proc_p->file_p[i] = file_p;
		}

		// rm file == NULL
		{
			int i, cnt = 0;
			for (i = 0; i < proc_p->cnt; ++i) {
				if (proc_p->file_p[i] == NULL) {
					continue;
				}
				++cnt;
			}

			if (cnt != proc_p->cnt) {
				int j = 0;
				struct file_probes **file_p_tmp = kmalloc(sizeof(*proc_p->file_p)*cnt, GFP_ATOMIC);

				for (i = 0; i < proc_p->cnt; ++i) {
					if (proc_p->file_p[i] == NULL) {
						continue;
					}

					file_p_tmp[j] = proc_p->file_p[i];
					++j;
				}

				proc_p->cnt = j;
				kfree(proc_p->file_p);
				proc_p->file_p = file_p_tmp;
			}
		}
	}

	print_proc_probes(proc_p);

	printk("####### get  END  #######\n");

	kfree(tmp_page_probes_table);

	return proc_p;
}

static struct proc_probes *proc_probes_copy(struct proc_probes *proc_p)
{
	size_t i;
	struct proc_probes *proc_p_out = kmalloc(sizeof(*proc_p_out), GFP_ATOMIC);

	proc_p_out->dentry = proc_p->dentry;
	proc_p_out->cnt = proc_p->cnt;

	proc_p_out->file_p = kmalloc(proc_p_out->cnt * sizeof(*proc_p_out->file_p), GFP_ATOMIC);

	for (i = 0; i < proc_p_out->cnt; ++i) {
		proc_p_out->file_p[i] = file_p_copy(proc_p->file_p[i]);
	}

	return proc_p_out;
}

static struct file_probes *proc_p_find_file_p(struct proc_probes *proc_p, struct vm_area_struct *vma)
{
	struct file_probes *file_p;
	size_t i;
	for (i = 0; i < proc_p->cnt; ++i) {
		file_p = proc_p->file_p[i];
		if (file_p == NULL) {
			continue;
		}

		if (vma->vm_file->f_dentry == file_p->dentry) {
			return file_p;
		}
	}

	return NULL;
}

static int register_usprobe_my(struct task_struct *task, us_proc_ip_t *ip)
{
	ip->installed = 0;
	ip->name = 0;

	return register_usprobe(task, ip, 1);
}

static int unregister_usprobe_my(struct task_struct *task, us_proc_ip_t *ip, enum US_FLAGS flag)
{
	int err = 0;

	switch (flag) {
	case US_UNREGS_PROBE:
		err = unregister_usprobe(task, ip, 1, 0);
		break;
	case US_NOT_RP2:
		err = unregister_usprobe(task, ip, 1, 1);
		break;
	case US_DISARM:
		arch_disarm_uprobe(&ip->jprobe.kp, task);
		break;
	default:
		panic("incorrect value flag=%d", flag);
	}

	return err;
}

// debug
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

static void print_page_probes(const struct page_probes *page_p)
{
	int i = 0;
	us_proc_ip_t *ip;

	printk("###     offset=%x\n", page_p->offset);
	list_for_each_entry(ip, &page_p->ip_list, list) {

		printk("###       addr[%2d]=%x, J_addr=%x, R_addr=%x\n",
				i, ip->offset, ip->jprobe.kp.addr, ip->retprobe.kp.addr);
		print_jprobe(&ip->jprobe);
		print_retprobe(&ip->retprobe);
		++i;
	}
}

static const char *NA = "N/A";

static void print_file_probes(const struct file_probes *file_p)
{
	int i, table_size;
	struct page_probes *page_p = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;

	if (file_p == NULL) {
		printk("### file_p == NULL\n");
		return;
	}

	table_size = (1 << file_p->page_probes_hash_bits);
	const char *name = (file_p->dentry) ? file_p->dentry->d_iname : NA;

	printk("### print_file_probes: path=%s, d_iname=%s, table_size=%d, vm_start=%x\n",
			file_p->path, name, table_size, file_p->vm_start);

	for (i = 0; i < table_size; ++i) {
		head = &file_p->page_probes_table[i];
		hlist_for_each_entry_rcu(page_p, node, head, hlist) {
			print_page_probes(page_p);
		}
	}
}

static void print_proc_probes(const struct proc_probes *proc_p)
{
	int i;

	printk("### print_proc_probes\n");
	for (i = 0; i < proc_p->cnt; ++i) {
		print_file_probes(proc_p->file_p[i]);
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
			us_proc_ip_t *ips = &lib->p_ips[j];
			unsigned long offset = ips->offset;
			printk("###         offset=%x\n", offset);
		}
	}
	printk("### BUNDLE PRINT  END  ###\n");
}

#endif /* __NEW_DPF__ */
