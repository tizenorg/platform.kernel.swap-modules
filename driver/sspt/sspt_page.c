#include "sspt_page.h"
#include "ip.h"
#include <linux/slab.h>
#include <linux/list.h>

struct sspt_page *sspt_page_create(unsigned long offset)
{
	struct sspt_page *obj = kmalloc(sizeof(*obj), GFP_ATOMIC);
	if (obj) {
		INIT_LIST_HEAD(&obj->ip_list);
		obj->offset = offset;
		obj->install = 0;
		spin_lock_init(&obj->lock);
		INIT_HLIST_NODE(&obj->hlist);
	}

	return obj;
}

void sspt_page_free(struct sspt_page *page)
{
	struct us_ip *ip, *n;

	list_for_each_entry_safe(ip, n, &page->ip_list, list) {
		list_del(&ip->list);
		free_ip(ip);
	}

	kfree(page);
}

struct sspt_page *sspt_page_copy(const struct sspt_page *page)
{
	struct us_ip *ip_in, *ip_out;
	struct sspt_page *page_out = kmalloc(sizeof(*page_out), GFP_ATOMIC);

	if (page_out) {
		INIT_LIST_HEAD(&page_out->ip_list);
		list_for_each_entry(ip_in, &page->ip_list, list) {
			ip_out = copy_ip(ip_in);
			if (ip_out == NULL) {
				// FIXME: free ip_list in page_p_out
				kfree(page_out);
				return NULL;
			}

			list_add(&ip_out->list, &page_out->ip_list);
		}

		page_out->offset = page->offset;
		page_out->install = 0;
		spin_lock_init(&page_out->lock);
		INIT_HLIST_NODE(&page_out->hlist);
	}

	return page_out;
}

void sspt_add_ip(struct sspt_page *page, struct us_ip *ip)
{
	ip->offset &= ~PAGE_MASK;
	INIT_LIST_HEAD(&ip->list);
	list_add(&ip->list, &page->ip_list);
}

struct us_ip *sspt_find_ip(struct sspt_page *page, unsigned long offset)
{
	struct us_ip *ip;

	list_for_each_entry(ip, &page->ip_list, list) {
		if (ip->offset == offset) {
			return ip;
		}
	}

	return NULL;
}

