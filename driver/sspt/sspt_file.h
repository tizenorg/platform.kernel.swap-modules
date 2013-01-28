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


struct sspt_file *sspt_file_create(const char *path, struct dentry *dentry, int page_cnt);
struct sspt_file *sspt_file_copy(const struct sspt_file *file);
void sspt_file_free(struct sspt_file *file);

struct sspt_page *sspt_find_page_mapped(struct sspt_file *file, unsigned long page);
void sspt_file_add_ip(struct sspt_file *file, struct ip_data *ip_d);

struct sspt_page *sspt_get_page(struct sspt_file *file, unsigned long offset_addr);
void sspt_put_page(struct sspt_page *page);

#endif /* __FILE_PROBES__ */
