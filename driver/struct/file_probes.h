#ifndef __FILE_PROBES__
#define __FILE_PROBES__

#include "ip.h"
#include <linux/types.h>


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


struct file_probes *file_p_new(const char *path, struct dentry *dentry, int page_cnt);
struct file_probes *file_p_copy(const struct file_probes *file_p);
void file_p_del(struct file_probes *file_p);

struct page_probes *file_p_find_page_p_mapped(struct file_probes *file_p, unsigned long page);
void file_p_add_probe(struct file_probes *file_p, struct ip_data *ip_d);

struct page_probes *get_page_p(struct file_probes *file_p, unsigned long offset_addr);
void put_page_p(struct page_probes *page_p);

#endif /* __FILE_PROBES__ */
