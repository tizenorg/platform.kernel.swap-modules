#include "ip.h"

struct us_ip *create_ip(unsigned long offset)
{
	struct us_ip *ip = kmalloc(sizeof(*ip), GFP_ATOMIC);
	memset(ip, 0, sizeof(*ip));

	INIT_LIST_HEAD(&ip->list);
	ip->offset = offset;

	return ip;
}

void free_ip(struct us_ip *ip)
{
	kfree(ip);
}

static inline void set_ip_jp_handler(struct us_ip *ip, kprobe_pre_entry_handler_t per_entry, void *entry)
{
	ip->jprobe.pre_entry = per_entry;
	ip->jprobe.entry = entry;
}

static inline void set_ip_rp_handler(struct us_ip *ip, kretprobe_handler_t handler)
{
	ip->flag_retprobe = 1;
	ip->retprobe.handler = handler;
}

static inline void set_ip_got_addr(struct us_ip *ip, unsigned long got_addr)
{
	ip->got_addr = got_addr;
}

struct us_ip *copy_ip(const struct us_ip *ip)
{
	struct us_ip *new_ip = create_ip(ip->offset);

	if (new_ip == NULL) {
		printk("us_proc_ip_copy: No enough memory\n");
		return NULL;
	}

	// jprobe
	set_ip_jp_handler(new_ip, ip->jprobe.pre_entry, ip->jprobe.entry);

	// retprobe
	if (ip->flag_retprobe) {
		retprobe_init(&new_ip->retprobe, ip->retprobe.handler);
	}

	return new_ip;
}

struct us_ip *create_ip_by_ip_data(struct ip_data *ip_d)
{
	struct us_ip *ip = create_ip(ip_d->offset);
	set_ip_jp_handler(ip, ip_d->pre_handler, ip_d->jp_handler);

	if (ip_d->flag_retprobe) {
		set_ip_rp_handler(ip, ip_d->rp_handler);
	}

	set_ip_got_addr(ip, ip_d->got_addr);

	return ip;
}
