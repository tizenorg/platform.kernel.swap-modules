#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/list.h>


//struct addr_probe {
//	unsigned long addr;
//
//	struct hlist_node node; // for page_probes
//};

struct us_proc_ip {
//	char *name;
//	int installed;
	struct jprobe jprobe;
	struct kretprobe retprobe;
	unsigned long addr;
};

struct page_probes {
	unsigned long page;
	unsigned long offset;

	struct hlist_node node; // for file_probes
//	struct hlist_head head; // for addr_probe

	size_t cnt_ip;
	struct us_proc_ip *ip;
};

struct file_probes {
	struct dentry *dentry;

	struct hlist_head head; // for page_probes
};

struct proc_probes {
	size_t cnt;
	struct file_probes **fp;
};

// addr_probe
//static struct addr_probe *ap_new(unsigned long addr)
//{
//	struct addr_probe *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);
//
//	if (obj) {
//		obj->addr = addr;
//		INIT_HLIST_NODE(&obj->node);
//	}
//
//	return obj;
//}
//
//static void ap_del(struct addr_probe *ap)
//{
//	// TODO: del
//}
// addr_probe

// page_probes
static struct page_probes *pp_new(unsigned long page, struct us_proc_ip *ip, size_t cnt)
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

static void pp_del(struct page_probes *pp)
{
	// TODO: del
}
// page_probes

void pp_set_all_kp_addr(struct page_probes *pp)
{
	struct us_proc_ip *ip;
	unsigned long addr;
	size_t i;
	for (i = 0; i < pp->cnt_ip; ++i) {
		ip = &pp->ip[i];
		addr = ip->addr + pp->offset;
		ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
	}
}

// file_probes
static struct file_probes *fp_new(struct dentry *dentry)
{
	struct file_probes *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);

	if (obj) {
		obj->dentry = dentry;
		INIT_HLIST_HEAD(&obj->head);
	}

	return obj;
}

static void fp_del(struct file_probes *fp)
{
	// TODO: del
}

static void fp_add_pp(struct file_probes *fp, struct page_probes *pp)
{
	hlist_add_head(&pp->node, &fp->head);
}

static struct page_probes *fp_find_pp(struct file_probes *fp, unsigned long page, unsigned long start_addr)
{
	struct page_probes *pp = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = &fp->head;
	unsigned long pp_page;

	hlist_for_each_entry(pp, node, head, node) {
		pp_page = start_addr > pp->page ? start_addr + pp->page : pp->page;
		if (pp_page == page) {
			pp->offset = start_addr > pp->page ? start_addr : 0;
//			pp->
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

static struct page_probes *get_pp_of_ips(unsigned long page, unsigned long min_index, unsigned long max_index, us_proc_ip_t *p_ips)
{
	struct page_probes *pp;
	unsigned long idx;
	unsigned long cnt = max_index - min_index;
	struct us_proc_ip *ip = kmalloc(sizeof(*ip)*cnt, GFP_ATOMIC);

	printk("#### min_index=%2u, max_index=%2u, cnt=%2u\n", min_index, max_index, cnt);
	for (idx = min_index; idx < max_index; ++idx) {
		ip[idx - min_index].addr = p_ips[idx].offset;
		ip[idx - min_index].jprobe = p_ips[idx].jprobe;
		ip[idx - min_index].retprobe = p_ips[idx].retprobe;
	}

	pp = pp_new(page, ip, cnt);
	kfree(ip);
	return pp;
}

struct proc_probes *get_file_probes(const inst_us_proc_t *task_inst_info)
{
	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	if (proc_p) {
		int i;
		proc_p->cnt = task_inst_info->libs_count;
		proc_p->fp = kmalloc(sizeof(*proc_p->fp)*proc_p->cnt, GFP_ATOMIC);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct file_probes *fp = fp_new(p_libs->m_f_dentry);
			unsigned long page = 0, min_index = 0, max_index = 0, cnt = 0, idx = 0;
			struct page_probes *pp = NULL;
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
					pp = get_pp_of_ips(page, min_index, max_index, p_libs->p_ips);
					fp_add_pp(fp, pp);

					page = addr & PAGE_MASK;
					min_index = max_index;
				}
			}

			max_index = p_libs->ips_count;
			pp = get_pp_of_ips(page, min_index, max_index, p_libs->p_ips);
			fp_add_pp(fp, pp);

			proc_p->fp[i] = fp;
		}
	}

	return proc_p;
}

// debug
//static void print_addr_probe(const struct addr_probe *ap)
//{
//	printk("###       addr=%x\n", ap->addr);
//}

static void print_page_probes(const struct page_probes *pp)
{
//	struct addr_probe *ap = NULL;
//	struct hlist_node *node = NULL;
//	struct hlist_head *head = &pp->head;
	int i;

	printk("###     page=%x, offset=%x\n", pp->page, pp->offset);
	for (i = 0; i < pp->cnt_ip; ++i) {
		printk("###       addr[%2d]=%x\n", i, pp->ip[i].addr);
	}


//	hlist_for_each_entry(ap, node, head, node) {
//		print_addr_probe(ap);
//	}
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
		print_file_probes(pp->fp[i]);
	}
	printk("### print_proc_probes\n");
}

#endif/* __NEW_DPF__ */
