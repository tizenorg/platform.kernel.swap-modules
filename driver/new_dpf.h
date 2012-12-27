#ifndef __NEW_DPF__
#define __NEW_DPF__

#include <linux/hash.h>
#include "storage.h"

enum US_FLAGS {
	US_UNREGS_PROBE,
	US_NOT_RP2,
	US_DISARM
};

struct probe_data {
	unsigned long offset;
	unsigned long got_addr;

	kprobe_pre_entry_handler_t pre_handler;
	unsigned long jp_handler;
	kretprobe_handler_t rp_handler;

	unsigned flag_retprobe:1;
};

struct page_probes {
	struct list_head ip_list;
	unsigned long offset;
	int install;
	spinlock_t lock;

	struct hlist_node hlist; // for file_probes
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

us_proc_ip_t *us_proc_ip_copy(const us_proc_ip_t *ip)
{
	us_proc_ip_t *ip_out = kmalloc(sizeof(*ip_out), GFP_ATOMIC);
	if (ip_out == NULL) {
		DPRINTF ("us_proc_ip_copy: No enough memory");
		return NULL;
	}

	memcpy (ip_out, ip, sizeof(*ip_out));

	// jprobe
	memset(&ip_out->jprobe, 0, sizeof(struct jprobe));
	ip_out->jprobe.entry = ip->jprobe.entry;
	ip_out->jprobe.pre_entry = ip->jprobe.pre_entry;

	// retprobe
	retprobe_init(&ip_out->retprobe, ip->retprobe.handler);

	ip_out->flag_got = 0;

	ip_out->installed = 0;
	INIT_LIST_HEAD(&ip_out->list);

	return ip_out;
}

us_proc_ip_t *us_proc_ips_copy(const us_proc_ip_t *ips, int cnt)
{
	int i;
	us_proc_ip_t *ips_out =
		kmalloc (cnt * sizeof (us_proc_ip_t), GFP_ATOMIC);

	if (!ips_out) {
		DPRINTF ("No enough memory for copy_info->p_libs[i].p_ips");
		return NULL;
	}

	memcpy (ips_out, ips, cnt * sizeof (us_proc_ip_t));
	for (i = 0; i < cnt; ++i) {
		ips_out[i].installed = 0;

		// jprobe
		memset(&ips_out[i].jprobe, 0, sizeof(struct jprobe));
		ips_out[i].jprobe.entry = ips[i].jprobe.entry;
		ips_out[i].jprobe.pre_entry = ips[i].jprobe.pre_entry;

		// retprobe
		retprobe_init(&ips_out[i].retprobe, ips[i].retprobe.handler);
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

static struct page_probes *page_p_copy(const struct page_probes *page_p)
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

static void page_p_add_ip(struct page_probes *page_p, us_proc_ip_t *ip)
{
	ip->offset &= ~PAGE_MASK;
	INIT_LIST_HEAD(&ip->list);
	list_add(&ip->list, &page_p->ip_list);
}

static us_proc_ip_t *page_p_find_ip(struct page_probes *page_p, unsigned long offset)
{
	us_proc_ip_t *ip;

	list_for_each_entry(ip, &page_p->ip_list, list) {
		if (ip->offset == offset) {
			return ip;
		}
	}

	return NULL;
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

static void set_ip_kp_addr(us_proc_ip_t *ip, struct page_probes *page_p, const struct file_probes *file_p)
{
	unsigned long addr = file_p->vm_start + page_p->offset + ip->offset;
	ip->retprobe.kp.addr = ip->jprobe.kp.addr = addr;
}

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
			hlist_for_each_entry_rcu(page_p, node, head, hlist) {
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
	hlist_for_each_entry_rcu(page_p, node, head, hlist) {
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

void file_p_add_probe(struct file_probes *file_p, struct probe_data *pd)
{
	unsigned long offset = pd->offset & PAGE_MASK;
	struct page_probes *page_p = file_p_find_page_p_or_new(file_p, offset);

	// FIXME: ip
	us_proc_ip_t *ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	memset(ip, 0, sizeof(*ip));

	INIT_LIST_HEAD(&ip->list);
	ip->flag_retprobe = pd->flag_retprobe;
	ip->flag_got = 0;
	ip->offset = pd->offset;
	ip->got_addr = pd->got_addr;
	ip->jprobe.pre_entry = pd->pre_handler;
	ip->jprobe.entry = pd->jp_handler;
	ip->retprobe.handler = pd->rp_handler;

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
static void proc_p_init(struct proc_probes *proc_p, struct dentry* dentry, pid_t tgid)
{
	INIT_LIST_HEAD(&proc_p->list);
	proc_p->tgid = tgid;
	proc_p->dentry = dentry;
	INIT_LIST_HEAD(&proc_p->file_list);
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
		struct dentry* dentry, struct probe_data *pd, int cnt)
{
	int i;
	struct file_probes *file_p = proc_p_find_file_p_by_dentry(proc_p, pach, dentry);

	for (i = 0; i < cnt; ++i) {
		file_p_add_probe(file_p, &pd[i]);
	}
}

static struct proc_probes *proc_p_copy(struct proc_probes *proc_p, struct task_struct *task)
{
	struct file_probes *file_p;
	struct proc_probes *proc_p_out = kmalloc(sizeof(*proc_p_out), GFP_ATOMIC);

	proc_p_init(proc_p_out, proc_p->dentry, task->tgid);

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
	struct proc_probes *proc_p = kmalloc(sizeof(*proc_p), GFP_ATOMIC);

	printk("####### get START #######\n");

	if (proc_p) {
		int i;
		proc_p_init(proc_p, task_inst_info->m_f_dentry, 0);

		printk("#2# get_file_probes: proc_p[dentry=%p]\n", proc_p->dentry);

		for (i = 0; i < task_inst_info->libs_count; ++i) {
			int k, j;
			us_proc_lib_t *p_libs = &task_inst_info->p_libs[i];
			struct dentry *dentry = p_libs->m_f_dentry;
			const char *pach = p_libs->path;

			for (k = 0; k < p_libs->ips_count; ++k) {
				struct probe_data pd;
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
			us_proc_ip_t *ips = &lib->p_ips[j];
			unsigned long offset = ips->offset;
			printk("###         offset=%x\n", offset);
		}
	}
	printk("### BUNDLE PRINT  END  ###\n");
}

#endif /* __NEW_DPF__ */
