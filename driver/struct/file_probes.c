#include "file_probes.h"
#include "page_probes.h"
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>


static int calculation_hash_bits(int cnt)
{
	int bits;
	for (bits = 1; cnt >>= 1; ++bits);

	return bits;
}

struct file_probes *file_p_new(const char *path, struct dentry *dentry, int page_cnt)
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

void file_p_del(struct file_probes *file_p)
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

struct file_probes *file_p_copy(const struct file_probes *file_p)
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

struct page_probes *file_p_find_page_p_mapped(struct file_probes *file_p, unsigned long page)
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

void file_p_add_probe(struct file_probes *file_p, struct ip_data *ip_d)
{
	unsigned long offset = ip_d->offset & PAGE_MASK;
	struct page_probes *page_p = file_p_find_page_p_or_new(file_p, offset);

	// FIXME: delete ip
	struct us_ip *ip = create_ip_by_ip_data(ip_d);

	page_p_add_ip(page_p, ip);
}

struct page_probes *get_page_p(struct file_probes *file_p, unsigned long offset_addr)
{
	unsigned long offset = offset_addr & PAGE_MASK;
	struct page_probes *page_p = file_p_find_page_p_or_new(file_p, offset);

	spin_lock(&page_p->lock);

	return page_p;
}

void put_page_p(struct page_probes *page_p)
{
	spin_unlock(&page_p->lock);
}

