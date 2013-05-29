#ifndef _KS_MANAGER_H
#define _KS_MANAGER_H

#include <dbi_kprobes.h>

struct kern_probe {
	struct jprobe jp;
	struct kretprobe rp;
};

int ksm_register_probe(unsigned long addr, void *pre_handler,
		       void *jp_handler, void *rp_handler);
int ksm_unregister_probe(unsigned long addr);

int ksm_unregister_probe_all(void);

#endif /* _KS_MANAGER_H */
