#include <linux/module.h>
#include <linux/slab.h>
#include <dbi_kprobes.h>
#include <dbi_kprobes_deps.h>
#include "ks_manager.h"

struct probe {
	struct hlist_node hlist;
	struct kern_probe p;
};

static HLIST_HEAD(list_probes);

static struct probe *create_probe(unsigned long addr, void *pre_handler,
				  void *jp_handler, void *rp_handler)
{
	struct probe *p = kzalloc(sizeof(*p), GFP_KERNEL);

	p->p.jp.kp.addr = p->p.rp.kp.addr = (void *)addr;
	p->p.jp.pre_entry = pre_handler;
	p->p.jp.entry = jp_handler;
	p->p.rp.handler = rp_handler;
	p->p.jp.priv_arg = p->p.rp.priv_arg = (void *)&p->p;
	INIT_HLIST_NODE(&p->hlist);

	return p;
}

static void free_probe(struct probe *p)
{
	kfree(p);
}

static void add_probe_to_list(struct probe *p)
{
	hlist_add_head(&p->hlist, &list_probes);
}

static void remove_probe_to_list(struct probe *p)
{
	hlist_del(&p->hlist);
}

static struct probe *find_probe(unsigned long addr)
{
	struct probe *p;
	struct hlist_node *node;

	/* check if such probe does exist */
	swap_hlist_for_each_entry(p, node, &list_probes, hlist)
		if (p->p.jp.kp.addr == addr)
			return p;

	return NULL;
}

int ksm_register_probe(unsigned long addr, void *pre_handler,
		       void *jp_handler, void *rp_handler)
{
	int ret;
	struct probe *p;

	p = create_probe(addr, pre_handler, jp_handler, rp_handler);
	if (!p)
		return -ENOMEM;

	ret = dbi_register_jprobe(&p->p.jp);
	if (ret)
		return ret;

	ret = dbi_register_kretprobe(&p->p.rp);
	if (ret)
		dbi_unregister_jprobe(&p->p.jp);
	else
		add_probe_to_list(p);

	return ret;
}
EXPORT_SYMBOL_GPL(ksm_register_probe);

static void do_ksm_unregister_probe(struct probe *p)
{
	remove_probe_to_list(p);
	dbi_unregister_kretprobe(&p->p.rp);
	dbi_unregister_jprobe(&p->p.jp);
	free_probe(p);
}

int ksm_unregister_probe(unsigned long addr)
{
	struct probe *p;

	p = find_probe(addr);
	if (p)
		return -EINVAL;

	do_ksm_unregister_probe(p);

	return 0;
}
EXPORT_SYMBOL_GPL(ksm_unregister_probe);

int ksm_unregister_probe_all(void)
{
	struct probe *p;
	struct hlist_node *node, *n;

	swap_hlist_for_each_entry_safe(p, node, n, &list_probes, hlist) {
		do_ksm_unregister_probe(p);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ksm_unregister_probe_all);

static int __init init_ks_manager(void)
{
       return 0;
}

static void __exit exit_ks_manager(void)
{
	ksm_unregister_probe_all();
}

module_init(init_ks_manager);
module_exit(exit_ks_manager);

MODULE_LICENSE ("GPL");
