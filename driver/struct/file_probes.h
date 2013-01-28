#ifndef __FILE_PROBES__
#define __FILE_PROBES__

#include "ip.h"
#include <linux/types.h>


struct sspt_file {
	struct list_head list;			// for proc_probes
	struct dentry *dentry;
	char *path;
	int loaded;
	unsigned long vm_start;
	unsigned long vm_end;

	unsigned long page_probes_hash_bits;
	struct hlist_head *page_probes_table; // for page_probes
};


struct sspt_file *file_p_new(const char *path, struct dentry *dentry, int page_cnt);
struct sspt_file *file_p_copy(const struct sspt_file *file);
void file_p_del(struct sspt_file *file);

struct sspt_page *file_p_find_page_p_mapped(struct sspt_file *file, unsigned long page);
void file_p_add_probe(struct sspt_file *file, struct ip_data *ip_d);

struct sspt_page *get_page_p(struct sspt_file *file, unsigned long offset_addr);
void put_page_p(struct sspt_page *page);

#endif /* __FILE_PROBES__ */
