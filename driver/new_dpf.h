#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/hash.h>
#include "storage.h"

struct page_probes {
	unsigned long offset;
	size_t cnt_ip;
	us_proc_ip_t *ip;
	int install;

	struct hlist_node hlist; // for file_probes
};

struct file_probes {
	struct dentry *dentry;
	char *path;
	int loaded;
	unsigned long map_addr;

	unsigned long page_probes_hash_bits;
	struct hlist_head *page_probes_table; // for page_probes
};

struct proc_probes {
	struct dentry *dentry;
	size_t cnt;
	struct file_probes **file_p;
};


// page_probes
static struct page_probes *page_p_new(unsigned long offset, us_proc_ip_t *ip, size_t cnt)
{
	struct page_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);

	if (obj) {
		int i;
		obj->ip = kmalloc(sizeof(*obj->ip)*cnt, GFP_ATOMIC);
		if(obj->ip == NULL) {
			kfree(obj);
			return NULL;
		}

		memcpy(obj->ip, ip, sizeof(*obj->ip)*cnt);
		obj->cnt_ip = cnt;
		obj->offset = offset;
		obj->install = 0;
		INIT_HLIST_NODE(&obj->hlist);
	}

	return obj;
}

static void page_p_del(struct page_probes *page_p)
{
	// TODO: del
}

static void page_p_assert_install(const struct page_probes *page_p)
{
	if (page_p->install != 0) {
		panic("already installed page %x\n", page_p->offset);
	}
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
	size_t i;
	for (i = 0; i < page_p->cnt_ip; ++i) {
		ip = &page_p->ip[i];
		addr = file_p->map_addr + page_p->offset + ip->offset;
		ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
//		printk("###       pp_set_all_kp_addr: start=%x, page=%x, offset=%x, addr=%x\n",
//				start, page_p->page, ip->offset, addr);
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
		obj->map_addr = 0;

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

static struct page_probes *file_p_find_page_p(struct file_probes *file_p, unsigned long page)
{
	struct page_probes *page_p;
	struct hlist_node *node;
	struct hlist_head *head;
	unsigned long offset;

	if (file_p->map_addr > page) {
		// TODO: or panic?!
		printk("ERROR: file_p->map_addr > page\n");
		return NULL;
	}

	offset = page - file_p->map_addr;

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
#include <linux/sort.h>

static int cmp_func(const void *a, const void *b)
{
	us_proc_ip_t *p_ips_a = a;
	us_proc_ip_t *p_ips_b = b;

	if (p_ips_a->offset < p_ips_b->offset) {
		return -1;
	}

	if (p_ips_a->offset > p_ips_b->offset) {
		return 1;
	}

	return 0;
}

static void print_libs(us_proc_lib_t *p_libs, const char *prefix)
{
	int k;
	for (k = 0; k < p_libs->ips_count; ++k) {
		us_proc_ip_t *p_ips = &p_libs->p_ips[k];
		unsigned long addr = p_ips->offset;
		printk("### %s tgid=%u addr = %x\n", prefix, current->tgid, addr);
	}
}

static void sort_libs(us_proc_lib_t *p_libs)
{
//	print_libs(p_libs, "no_sort");
	sort(p_libs->p_ips, p_libs->ips_count, sizeof(*p_libs->p_ips), &cmp_func, NULL);
//	print_libs(p_libs, "sort");
}

#include "storage.h"

static struct page_probes *get_page_p_of_ips(unsigned long page, unsigned long min_index, unsigned long max_index, us_proc_ip_t *p_ips)
{
	struct page_probes *page_p;
	unsigned long idx;
	unsigned long cnt = max_index - min_index;
	us_proc_ip_t *ip = kmalloc(sizeof(*ip)*cnt, GFP_ATOMIC);

	for (idx = min_index; idx < max_index; ++idx) {
		ip[idx - min_index].offset = p_ips[idx].offset & ~PAGE_MASK;;
		ip[idx - min_index].jprobe = p_ips[idx].jprobe;
		ip[idx - min_index].retprobe = p_ips[idx].retprobe;
	}

	page_p = page_p_new(page, ip, cnt);
	kfree(ip);
	return page_p;
}

static void print_proc_probes(const struct proc_probes *proc_p);

struct proc_probes *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	if (proc_p) {
		int i;
		proc_p->cnt = task_inst_info->libs_count;
		proc_p->dentry = task_inst_info->m_f_dentry;
		proc_p->file_p = kmalloc(sizeof(*proc_p->file_p)*proc_p->cnt, GFP_ATOMIC);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct file_probes *file_p = NULL;
			unsigned long page = 0, min_index = 0, max_index = 0, cnt = 0, idx = 0;
			struct page_probes *page_p = NULL;
			int k, page_cnt = 0;

			if (p_libs->ips_count == 0) {
				continue;
			}

			sort_libs(p_libs);

			// calculation page_cnt
			page = p_libs->p_ips[0].offset & PAGE_MASK;
			min_index = 0;
			for (k = 0; k < p_libs->ips_count; ++k) {
				us_proc_ip_t *p_ips = &p_libs->p_ips[k];
				unsigned long addr = p_ips->offset;
				if ( page != (addr & PAGE_MASK)) {
					max_index = k;
					++page_cnt;

					page = addr & PAGE_MASK;
					min_index = max_index;
				}
			}

			++page_cnt;

			printk("### file: %s, page_cnt=%d\n", p_libs->m_f_dentry->d_iname, page_cnt);
			file_p = file_p_new(p_libs, page_cnt);

			page = p_libs->p_ips[0].offset & PAGE_MASK;
			min_index = 0;
			for (k = 0; k < p_libs->ips_count; ++k) {
				us_proc_ip_t *p_ips = &p_libs->p_ips[k];
				unsigned long addr = p_ips->offset;
				if ( page != (addr & PAGE_MASK)) {
					max_index = k;
					page_p = get_page_p_of_ips(page, min_index, max_index, p_libs->p_ips);

					file_p_add_page_p(file_p, page_p);

					page = addr & PAGE_MASK;
					min_index = max_index;
				}
			}

			max_index = p_libs->ips_count;
			page_p = get_page_p_of_ips(page, min_index, max_index, p_libs->p_ips);


			file_p_add_page_p(file_p, page_p);
			proc_p->file_p[i] = file_p;
		}
	}

	print_proc_probes(proc_p);

	return proc_p;
}

struct file_probes *proc_p_find_file_p(struct proc_probes *proc_p, struct vm_area_struct *vma)
{
	struct file_probes *file_p;
	size_t i;
	for (i = 0; i < proc_p->cnt; ++i) {
		file_p = proc_p->file_p[i];

		if (vma->vm_file->f_dentry == file_p->dentry) {
			return file_p;
		}
	}

	return NULL;
}

static int register_usprobe_my(struct task_struct *task, struct mm_struct *mm, us_proc_ip_t *ip)
{
	ip->installed = 0;
	ip->name = 0;

	return register_usprobe(task, mm, ip, 1, NULL);
}

static int unregister_usprobe_my(struct task_struct *task, us_proc_ip_t *ip)
{
	int err = unregister_usprobe(task, ip, 1);

//	ip->installed = 0;
	ip->name = 0;

	return err;
}

// debug
static void print_page_probes(const struct page_probes *pp)
{
	int i;

	printk("###     offset=%x\n", pp->offset);
	for (i = 0; i < pp->cnt_ip; ++i) {
		printk("###       addr[%2d]=%x, J_addr=%x, R_addr=%x\n",
				i, pp->ip[i].offset,
				pp->ip[i].jprobe.kp.addr, pp->ip[i].retprobe.kp.addr);
	}
}

static void print_file_probes(const struct file_probes *file_p)
{
	int i;
	struct page_probes *page_p = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;

	printk("###   d_iname=%s, map_addr=%x\n",
			file_p->dentry->d_iname, file_p->map_addr);

	for (i = 0; i < (1 << file_p->page_probes_hash_bits); ++i) {
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

#endif /* __NEW_DPF__ */
