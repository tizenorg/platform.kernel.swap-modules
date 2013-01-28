#ifndef __PAGE_PROBES__
#define __PAGE_PROBES__

#include <linux/types.h>
#include <linux/spinlock.h>

struct us_ip;

struct sspt_page {
	struct list_head ip_list;
	unsigned long offset;
	int install;
	spinlock_t lock;

	struct hlist_node hlist; // for file_probes
};

struct sspt_page *page_p_new(unsigned long offset);
struct sspt_page *page_p_copy(const struct sspt_page *page);
void page_p_del(struct sspt_page *page);

void page_p_add_ip(struct sspt_page *page, struct us_ip *ip);
struct us_ip *page_p_find_ip(struct sspt_page *page, unsigned long offset);

static void page_p_assert_install(const struct sspt_page *page)
{
	if (page->install != 0) {
		panic("already installed page %x\n", page->offset);
	}
}

static int page_p_is_install(struct sspt_page *page)
{
	return page->install;
}

static void page_p_installed(struct sspt_page *page)
{
	page->install = 1;
}

static void page_p_uninstalled(struct sspt_page *page)
{
	page->install = 0;
}

#endif /* __PAGE_PROBES__ */
