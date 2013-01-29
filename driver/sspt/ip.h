#ifndef __IP__
#define __IP__

#include <linux/list.h>
#include "../../kprobe/dbi_kprobes.h"

// TODO: tmp struct ip_data
struct ip_data {
	unsigned long offset;
	unsigned long got_addr;

	kprobe_pre_entry_handler_t pre_handler;
	unsigned long jp_handler;
	kretprobe_handler_t rp_handler;

	unsigned flag_retprobe:1;
};

struct sspt_page;
struct sspt_file;

struct us_ip {
	struct list_head list;

	struct jprobe jprobe;
	struct kretprobe retprobe;

	unsigned long offset;
	unsigned long got_addr;

	unsigned flag_retprobe:1;
	unsigned flag_got:1;
};


struct us_ip *create_ip(unsigned long offset);
struct us_ip *copy_ip(const struct us_ip *ip);
struct us_ip *create_ip_by_ip_data(struct ip_data *ip_d);
void free_ip(struct us_ip *ip);

void sspt_set_ip_addr(struct us_ip *ip, const struct sspt_page *page, const struct sspt_file *file);

#endif /* __IP__ */
