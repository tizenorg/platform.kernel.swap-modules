////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           probes_manager.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       probes_manager.c
//      AUTHOR:         L.Komkov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(__PROBES_MANAGER_H__)
#define __PROBES_MANAGER_H__

#include "ec_probe.h"
#include "probes.h"

typedef struct
{
	unsigned long addr;
	struct jprobe jprobe;
	struct kretprobe retprobe;
	struct hlist_node hlist;
} kernel_probe_t;

extern int add_probe(unsigned long addr,
		     unsigned long pre_handler,
		     unsigned long jp_handler,
		     unsigned long rp_handler);
extern int reset_probes(void);

int set_kernel_probes(void);
int unset_kernel_probes(void);

void dbi_install_user_handlers(void);
void dbi_uninstall_user_handlers(void);

#endif // !defined(__PROBES_MANAGER_H__)
