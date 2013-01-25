#ifndef __PAGE_PROBES__
#define __PAGE_PROBES__

#include <linux/types.h>
#include <linux/spinlock.h>

struct us_ip;

struct page_probes {
	struct list_head ip_list;
	unsigned long offset;
	int install;
	spinlock_t lock;

	struct hlist_node hlist; // for file_probes
};

struct page_probes *page_p_new(unsigned long offset);
struct page_probes *page_p_copy(const struct page_probes *page_p);
void page_p_del(struct page_probes *page_p);

void page_p_add_ip(struct page_probes *page_p, struct us_ip *ip);
struct us_ip *page_p_find_ip(struct page_probes *page_p, unsigned long offset);

static void page_p_assert_install(const struct page_probes *page_p)
{
	if (page_p->install != 0) {
		panic("already installed page %x\n", page_p->offset);
	}
}

static int page_p_is_install(struct page_probes *page_p)
{
	return page_p->install;
}

static void page_p_installed(struct page_probes *page_p)
{
	page_p->install = 1;
}

static void page_p_uninstalled(struct page_probes *page_p)
{
	page_p->install = 0;
}

#endif /* __PAGE_PROBES__ */
