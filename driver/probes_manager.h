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

extern int probes_manager_init (void);
extern void probes_manager_down (void);

extern int add_probe (unsigned long addr);
extern int reset_probes(void);
extern int remove_probe (unsigned long addr);

extern int attach_selected_probes (void);
extern int detach_selected_probes (void);

extern int register_kernel_probe (kernel_probe_t * probe);
extern int unregister_kernel_probe (kernel_probe_t * probe);

extern unsigned long def_jprobe_event_pre_handler (kernel_probe_t * probe, struct pt_regs *regs);
extern void def_jprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);
extern int def_retprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, kernel_probe_t * p);
void dbi_install_user_handlers(void);
void dbi_uninstall_user_handlers(void);
int is_pf_installed_by_user(void);
int install_kern_otg_probe(unsigned long addr,
			   unsigned long pre_handler,
			   unsigned long jp_handler,
			   unsigned long rp_handler);

extern unsigned long pf_addr;
extern unsigned long cp_addr;
extern unsigned long mr_addr;
extern unsigned long exit_addr;
extern unsigned long unmap_addr;
extern kernel_probe_t *pf_probe;
extern kernel_probe_t *mr_probe;
extern kernel_probe_t *exit_probe;
extern kernel_probe_t *unmap_probe;
extern unsigned int probes_flags;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
extern spinlock_t ec_probe_spinlock;
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */

enum {
	PROBE_FLAG_PF_INSTLD    = (1 << 0),
	PROBE_FLAG_MR_INSTLD    = (1 << 2),
	PROBE_FLAG_EXIT_INSTLD  = (1 << 3),
	PROBE_FLAG_UNMAP_INSTLD = (1 << 4)
};

#endif // !defined(__PROBES_MANAGER_H__)
