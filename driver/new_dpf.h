#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/list.h>

struct us_proc_ip {
	struct jprobe jprobe;
	struct kretprobe retprobe;
	unsigned long addr;
};

struct page_probes {
	unsigned long page;
	unsigned long offset;
	size_t cnt_ip;
	struct us_proc_ip *ip;

	struct hlist_node node; // for file_probes
};

struct file_probes {
	struct dentry *dentry;
	char *path;
	int loaded;

	struct hlist_head head; // for page_probes
};

struct proc_probes {
	size_t cnt;
	struct file_probes **file_p;
};


// page_probes
static struct page_probes *page_p_new(unsigned long page, struct us_proc_ip *ip, size_t cnt)
{
	struct page_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);
	printk("##### pp_new: page=%x, cnt_addr=%u\n", page, cnt);

	if (obj) {
		int i;
		obj->ip = kmalloc(sizeof(*obj->ip)*cnt, GFP_ATOMIC);
		if(obj->ip == NULL) {
			kfree(obj);
			return NULL;
		}

		memcpy(obj->ip, ip, sizeof(*obj->ip)*cnt);
		obj->cnt_ip = cnt;
		obj->page = page;
		obj->offset = 0;
		INIT_HLIST_NODE(&obj->node);
	}

	return obj;
}

static void page_p_del(struct page_probes *page_p)
{
	// TODO: del
}
// page_probes

static void page_p_set_all_kp_addr(struct page_probes *page_p)
{
	struct us_proc_ip *ip;
	unsigned long addr;
	size_t i;
	for (i = 0; i < page_p->cnt_ip; ++i) {
		ip = &page_p->ip[i];
		addr = ip->addr + page_p->offset;
		ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
//		printk("###       pp_set_all_kp_addr: addr=%x\n", addr);
	}
}

// file_probes
static struct file_probes *file_p_new(us_proc_lib_t *lib)
{
	struct file_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);

	if (obj) {
		obj->dentry = lib->m_f_dentry;
		obj->path = lib->path;
		obj->loaded = 0;
		INIT_HLIST_HEAD(&obj->head);
	}

	return obj;
}

static void file_p_del(struct file_probes *file_p)
{
	// TODO: del
}

static void file_p_add_page_p(struct file_probes *file_p, struct page_probes *page_p)
{
	hlist_add_head(&page_p->node, &file_p->head);
}

static struct page_probes *file_p_find_page_p(struct file_probes *file_p, unsigned long page, unsigned long start_addr)
{
	struct page_probes *pp = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = &file_p->head;
	unsigned long pp_page;

	hlist_for_each_entry(pp, node, head, node) {
		pp_page = start_addr > pp->page ? start_addr + pp->page : pp->page;
		if (pp_page == page) {
			pp->offset = start_addr > pp->page ? start_addr : 0;
			return pp;
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
	struct us_proc_ip *ip = kmalloc(sizeof(*ip)*cnt, GFP_ATOMIC);

	printk("#### min_index=%2u, max_index=%2u, cnt=%2u\n", min_index, max_index, cnt);
	for (idx = min_index; idx < max_index; ++idx) {
		ip[idx - min_index].addr = p_ips[idx].offset;
		ip[idx - min_index].jprobe = p_ips[idx].jprobe;
		ip[idx - min_index].retprobe = p_ips[idx].retprobe;
	}

	page_p = page_p_new(page, ip, cnt);
	kfree(ip);
	return page_p;
}

struct proc_probes *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	if (proc_p) {
		int i;
		proc_p->cnt = task_inst_info->libs_count;
		proc_p->file_p = kmalloc(sizeof(*proc_p->file_p)*proc_p->cnt, GFP_ATOMIC);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct file_probes *file_p = file_p_new(p_libs);
			unsigned long page = 0, min_index = 0, max_index = 0, cnt = 0, idx = 0;
			struct page_probes *page_p = NULL;
			int k;
			sort_libs(p_libs);

			if (p_libs->ips_count == 0) {
				continue;
			}

			page = p_libs->p_ips[0].offset & PAGE_MASK;
			printk("#### page=%x\n", page);
			min_index = 0;
			for (k = 0; k < p_libs->ips_count; ++k) {
				us_proc_ip_t *p_ips = &p_libs->p_ips[k];
				unsigned long addr = p_ips->offset;

				printk("#### k=%2u, addr=%x\n", k, addr);
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

static int register_usprobe_my(struct task_struct *task, struct mm_struct *mm, struct us_proc_ip *ip)
{
//	us_proc_ip_t ip_t;
//	ip_t.installed = 0;
//	ip_t.name = 0;
//	ip_t.jprobe = ip->jprobe;
//	ip_t.retprobe = ip->retprobe;
//	ip_t.offset = ip->addr;


	us_proc_ip_t *ip_t = kmalloc(sizeof(*ip_t), GFP_ATOMIC);
	ip_t->installed = 0;
	ip_t->name = 0;
	ip_t->jprobe = ip->jprobe;
	ip_t->retprobe = ip->retprobe;
	ip_t->offset = ip->addr;


	return register_usprobe(task, mm, ip_t, 1, NULL);
}

// debug
static void print_page_probes(const struct page_probes *pp)
{
	int i;

	printk("###     page=%x, offset=%x\n", pp->page, pp->offset);
	for (i = 0; i < pp->cnt_ip; ++i) {
		printk("###       addr[%2d]=%x, J_addr=%x, R_addr=%x\n",
				i, pp->ip[i].addr,
				pp->ip[i].jprobe.kp.addr, pp->ip[i].retprobe.kp.addr);
	}
}

static void print_file_probes(const struct file_probes *fp)
{
	struct page_probes *pp = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = &fp->head;

	printk("###   d_iname=%s\n", fp->dentry->d_iname);

	hlist_for_each_entry(pp, node, head, node) {
		print_page_probes(pp);
	}
}

static void print_proc_probes(const struct proc_probes *pp)
{
	int i;

	printk("### print_proc_probes\n");
	for (i = 0; i < pp->cnt; ++i) {
		print_file_probes(pp->file_p[i]);
	}
	printk("### print_proc_probes\n");
}

#endif /* __NEW_DPF__ */
