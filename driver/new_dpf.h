#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/hash.h>
#include "storage.h"

#include "struct/ip.h"
#include "struct/page_probes.h"

enum US_FLAGS {
	US_UNREGS_PROBE,
	US_NOT_RP2,
	US_DISARM
};




struct file_probes {
	struct list_head list;			// for proc_probes
	struct dentry *dentry;
	char *path;
	int loaded;
	unsigned long vm_start;
	unsigned long vm_end;

	unsigned long page_probes_hash_bits;
	struct hlist_head *page_probes_table; // for page_probes
};

struct proc_probes {
	struct list_head list;
	pid_t tgid;
	struct dentry *dentry;
	struct list_head file_list;
};




static void set_ip_kp_addr(struct us_ip *ip, struct page_probes *page_p, const struct file_probes *file_p)
{
	unsigned long addr = file_p->vm_start + page_p->offset + ip->offset;
	ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
}

static void page_p_set_all_kp_addr(struct page_probes *page_p, const struct file_probes *file_p)
{
	struct us_ip *ip;
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
static struct file_probes *file_p_new(const char *path, struct dentry *dentry, int page_cnt)
{
	struct file_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);

	if (obj) {
		int i, table_size;
		obj->path = path;
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

static void file_p_del(struct file_probes *file_p)
{
	struct hlist_node *p, *n;
	struct hlist_head *head;
	struct page_probes *page_p;
	int i, table_size = (1 << file_p->page_probes_hash_bits);

	for (i = 0; i < table_size; ++i) {
		head = &file_p->page_probes_table[i];
		hlist_for_each_entry_safe(page_p, p, n, head, hlist) {
			hlist_del(&page_p->hlist);
			page_p_del(page_p);
		}
	}

	kfree(file_p->page_probes_table);
	kfree(file_p);
}

static void file_p_add_page_p(struct file_probes *file_p, struct page_probes *page_p)
{
	hlist_add_head(&page_p->hlist, &file_p->page_probes_table[hash_ptr(page_p->offset, file_p->page_probes_hash_bits)]);
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
		INIT_LIST_HEAD(&file_p_out->list);
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
			hlist_for_each_entry(page_p, node, head, hlist) {
				file_p_add_page_p(file_p_out, page_p_copy(page_p));
			}
		}
	}

	return file_p_out;
}

static struct page_probes *file_p_find_page_p(struct file_probes *file_p, unsigned long offset)
{
	struct hlist_node *node;
	struct hlist_head *head;
	struct page_probes *page_p;

	head = &file_p->page_probes_table[hash_ptr(offset, file_p->page_probes_hash_bits)];
	hlist_for_each_entry(page_p, node, head, hlist) {
		if (page_p->offset == offset) {
			return page_p;
		}
	}

	return NULL;
}

static struct page_probes *file_p_find_page_p_or_new(struct file_probes *file_p, unsigned long offset)
{
	struct page_probes *page_p = file_p_find_page_p(file_p, offset);

	if (page_p == NULL) {
		page_p = page_p_new(offset);
		file_p_add_page_p(file_p, page_p);
	}

	return page_p;
}

static struct page_probes *file_p_find_page_p_mapped(struct file_probes *file_p, unsigned long page)
{
	unsigned long offset;

	if (file_p->vm_start > page || file_p->vm_end < page) {
		// TODO: or panic?!
		printk("ERROR: file_p[vm_start..vm_end] <> page: file_p[vm_start=%x, vm_end=%x, path=%s, d_iname=%s] page=%x\n",
				file_p->vm_start, file_p->vm_end, file_p->path, file_p->dentry->d_iname, page);
		return NULL;
	}

	offset = page - file_p->vm_start;

	return file_p_find_page_p(file_p, offset);
}

static void file_p_add_probe(struct file_probes *file_p, struct ip_data *ip_d)
{
	unsigned long offset = ip_d->offset & PAGE_MASK;
	struct page_probes *page_p = file_p_find_page_p_or_new(file_p, offset);

	// FIXME: delete ip
	struct us_ip *ip = create_ip_by_ip_data(ip_d);

	page_p_add_ip(page_p, ip);
}

static struct page_probes *get_page_p(struct file_probes *file_p, unsigned long offset_addr)
{
	unsigned long offset = offset_addr & PAGE_MASK;
	struct page_probes *page_p = file_p_find_page_p_or_new(file_p, offset);

	spin_lock(&page_p->lock);

	return page_p;
}

static void put_page_p(struct page_probes *page_p)
{
	spin_unlock(&page_p->lock);
}
// file_probes

// proc_probes
static struct proc_probes *proc_p_create(struct dentry* dentry, pid_t tgid)
{
	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	if (proc_p) {
		INIT_LIST_HEAD(&proc_p->list);
		proc_p->tgid = tgid;
		proc_p->dentry = dentry;
		INIT_LIST_HEAD(&proc_p->file_list);
	}

	return proc_p;
}

static void proc_p_free(struct proc_probes *proc_p)
{
	struct file_probes *file_p, *n;
	list_for_each_entry_safe(file_p, n, &proc_p->file_list, list) {
		list_del(&file_p->list);
		file_p_del(file_p);
	}

	kfree(proc_p);
}

extern struct list_head proc_probes_list;

void proc_p_free_all(void)
{
	if (strcmp(us_proc_info.path,"*") == 0) {
		// app
		proc_p_free(us_proc_info.pp);
		us_proc_info.pp = NULL;
	} else {
		// libonly
		struct proc_probes *proc_p, *tmp;
		list_for_each_entry_safe(proc_p, tmp, &proc_probes_list, list) {
			list_del(&proc_p->list);
			proc_p_free(proc_p);
		}
	}
}

static void proc_p_add_file_p(struct proc_probes *proc_p, struct file_probes *file_p)
{
	list_add(&file_p->list, &proc_p->file_list);
}

static struct file_probes *proc_p_find_file_p_by_dentry(struct proc_probes *proc_p,
		const char *pach, struct dentry *dentry)
{
	struct file_probes *file_p;

	list_for_each_entry(file_p, &proc_p->file_list, list) {
		if (file_p->dentry == dentry) {
			return file_p;
		}
	}

	file_p = file_p_new(pach, dentry, 10);
	proc_p_add_file_p(proc_p, file_p);

	return file_p;
}

static void proc_p_add_dentry_probes(struct proc_probes *proc_p, const char *pach,
		struct dentry* dentry, struct ip_data *ip_d, int cnt)
{
	int i;
	struct file_probes *file_p = proc_p_find_file_p_by_dentry(proc_p, pach, dentry);

	for (i = 0; i < cnt; ++i) {
		file_p_add_probe(file_p, &ip_d[i]);
	}
}

static struct proc_probes *proc_p_copy(struct proc_probes *proc_p, struct task_struct *task)
{
	struct file_probes *file_p;
	struct proc_probes *proc_p_out = proc_p_create(proc_p->dentry, task->tgid);

	list_for_each_entry(file_p, &proc_p->file_list, list) {
		proc_p_add_file_p(proc_p_out, file_p_copy(file_p));
	}

	return proc_p_out;
}

static struct file_probes *proc_p_find_file_p(struct proc_probes *proc_p, struct vm_area_struct *vma)
{
	struct file_probes *file_p;

	list_for_each_entry(file_p, &proc_p->file_list, list) {
		if (vma->vm_file->f_dentry == file_p->dentry) {
			return file_p;
		}
	}

	return NULL;
}
// proc_probes

#include "storage.h"

static void print_proc_probes(const struct proc_probes *proc_p);

struct proc_probes *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct proc_probes *proc_p = proc_p_create(task_inst_info->m_f_dentry, 0);

	printk("####### get START #######\n");

	if (proc_p) {
		int i;

		printk("#2# get_file_probes: proc_p[dentry=%p]\n", proc_p->dentry);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			int k, j;
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct dentry *dentry = p_libs->m_f_dentry;
			const char *pach = p_libs->path;

			for (k = 0; k < p_libs->ips_count; ++k) {
				struct ip_data pd;
				us_proc_ip_t *ip = &p_libs->p_ips[k];
				unsigned long got_addr = 0;

				for (j = 0; j < p_libs->plt_count; ++j) {
					if (ip->offset == p_libs->p_plt[j].func_addr) {
						got_addr = p_libs->p_plt[j].got_addr;
						break;
					}
				}

				pd.flag_retprobe = 1;
				pd.offset = ip->offset;
				pd.got_addr = got_addr;
				pd.pre_handler = ip->jprobe.pre_entry;
				pd.jp_handler = ip->jprobe.entry;
				pd.rp_handler = ip->retprobe.handler;

				proc_p_add_dentry_probes(proc_p, pach, dentry, &pd, 1);
			}
		}
	}

	print_proc_probes(proc_p);

	printk("####### get  END  #######\n");

	return proc_p;
}

static int register_usprobe(struct task_struct *task, struct us_ip *ip, int atomic);
static int unregister_usprobe(struct task_struct *task, struct us_ip *ip, int atomic, int no_rp2);

static int register_usprobe_my(struct task_struct *task, struct us_ip *ip)
{
	return register_usprobe(task, ip, 1);
}

static int unregister_usprobe_my(struct task_struct *task, struct us_ip *ip, enum US_FLAGS flag)
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
	struct us_ip *ip;

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
	struct file_probes *file_p;

	printk("### print_proc_probes\n");
	list_for_each_entry(file_p, &proc_p->file_list, list) {
		print_file_probes(file_p);
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

#endif /* __NEW_DPF__ */
