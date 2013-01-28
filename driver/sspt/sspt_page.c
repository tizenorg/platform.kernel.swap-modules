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
	struct us_ip *ip, *new_ip;
	struct sspt_page *new_page = kmalloc(sizeof(*new_page), GFP_ATOMIC);

	if (new_page) {
		INIT_LIST_HEAD(&new_page->ip_list);
		list_for_each_entry(ip, &page->ip_list, list) {
			new_ip = copy_ip(ip);
			if (new_ip == NULL) {
				sspt_page_free(new_page);
				return NULL;
			}

			list_add(&new_ip->list, &new_page->ip_list);
		}

		new_page->offset = page->offset;
		new_page->install = 0;
		spin_lock_init(&new_page->lock);
		INIT_HLIST_NODE(&new_page->hlist);
	}

	return new_page;
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

