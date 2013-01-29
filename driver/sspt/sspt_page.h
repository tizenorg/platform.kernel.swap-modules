#ifndef __PAGE_PROBES__
#define __PAGE_PROBES__

#include <linux/types.h>
#include <linux/spinlock.h>

struct us_ip;
struct sspt_file;

struct sspt_page {
	struct list_head ip_list;
	unsigned long offset;
	int install;
	spinlock_t lock;

	struct hlist_node hlist; // for file_probes
};

struct sspt_page *sspt_page_create(unsigned long offset);
struct sspt_page *sspt_page_copy(const struct sspt_page *page);
void sspt_page_free(struct sspt_page *page);

void sspt_add_ip(struct sspt_page *page, struct us_ip *ip);
struct us_ip *sspt_find_ip(struct sspt_page *page, unsigned long offset);

static inline void sspt_page_assert_install(const struct sspt_page *page)
{
	if (page->install != 0) {
		panic("already installed page %x\n", page->offset);
	}
}

static inline int sspt_page_is_install(struct sspt_page *page)
{
	return page->install;
}

static inline void sspt_page_installed(struct sspt_page *page)
{
	page->install = 1;
}

static inline void sspt_page_uninstalled(struct sspt_page *page)
{
	page->install = 0;
}

void sspt_set_all_ip_addr(struct sspt_page *page, const struct sspt_file *file);

#endif /* __PAGE_PROBES__ */
