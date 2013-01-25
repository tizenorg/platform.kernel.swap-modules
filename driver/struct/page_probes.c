#include "page_probes.h"
#include "ip.h"
#include <linux/slab.h>
#include <linux/list.h>

struct page_probes *page_p_new(unsigned long offset)
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

void page_p_del(struct page_probes *page_p)
{
	struct us_ip *ip, *n;

	list_for_each_entry_safe(ip, n, &page_p->ip_list, list) {
		list_del(&ip->list);
		free_ip(ip);
	}
}

struct page_probes *page_p_copy(const struct page_probes *page_p)
{
	struct us_ip *ip_in, *ip_out;
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

void page_p_add_ip(struct page_probes *page_p, struct us_ip *ip)
{
	ip->offset &= ~PAGE_MASK;
	INIT_LIST_HEAD(&ip->list);
	list_add(&ip->list, &page_p->ip_list);
}

struct us_ip *page_p_find_ip(struct page_probes *page_p, unsigned long offset)
{
	struct us_ip *ip;

	list_for_each_entry(ip, &page_p->ip_list, list) {
		if (ip->offset == offset) {
			return ip;
		}
	}

	return NULL;
}

