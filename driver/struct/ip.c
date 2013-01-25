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

static void set_ip_jp_handler(struct us_ip *ip, kprobe_pre_entry_handler_t per_entry, void *entry)
{
	ip->jprobe.pre_entry = per_entry;
	ip->jprobe.entry = entry;
}

static void set_ip_rp_handler(struct us_ip *ip, kretprobe_handler_t handler)
{
	ip->flag_retprobe = 1;
	ip->retprobe.handler = handler;
}

static void set_ip_got_addr(struct us_ip *ip, unsigned long got_addr)
{
	ip->got_addr = got_addr;
}

struct us_ip *us_proc_ip_copy(const struct us_ip *ip)
{
	// FIXME: one malloc us_ip
	struct us_ip *ip_out = kmalloc(sizeof(*ip_out), GFP_ATOMIC);
	if (ip_out == NULL) {
		printk("us_proc_ip_copy: No enough memory\n");
		return NULL;
	}

	memcpy(ip_out, ip, sizeof(*ip_out));

	// jprobe
	memset(&ip_out->jprobe, 0, sizeof(struct jprobe));
	ip_out->jprobe.entry = ip->jprobe.entry;
	ip_out->jprobe.pre_entry = ip->jprobe.pre_entry;

	// retprobe
	retprobe_init(&ip_out->retprobe, ip->retprobe.handler);

	ip_out->flag_got = 0;

	INIT_LIST_HEAD(&ip_out->list);

	return ip_out;
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
