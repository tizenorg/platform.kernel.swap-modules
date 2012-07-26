////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           probes.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       probes.c
//      AUTHOR:         L.Komkov, S.Grekhov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef __PROBES_H__
#define __PROBES_H__

#include "ec_probe.h"
#include "storage.h"
#include "../kprobe/dbi_kprobes.h"

#ifndef regs_return_value
/* "regs_return_value" is ARCH-dependent. ARCH is passed via "EC_ARCH_*" */

#if defined(EC_ARCH_arm)    /* ARCH == arm */
#define regs_return_value(regs) ((regs)->ARM_r0)
#elif defined(EC_ARCH_i386) /* ARCH == i386 */
#define regs_return_value(regs) ((regs)->ax)
#elif defined(EC_ARCH_mips) /* ARCH == mips */
#define regs_return_value(regs) ((regs)->regs[2])
#else
#error "Cannot define -DEC_ARCH_$(ARCH) or architecture no supported"
#endif

#endif /* ndef regs_return_value */

extern struct jprobe my_jprobe[];
extern const char *ec_probe_name[];

extern struct kretprobe my_kretprobe[];

#define MY_JPROBE_ENTRY(handler_entry) { .entry = JPROBE_ENTRY(handler_entry) }

/* Probe up to 20 instances concurrently. */
#define MAXACTIVE 20

#define MY_RETPROBE_HANDLER(handler_entry) { .handler = (handler_entry), .maxactive = MAXACTIVE }

#define MY_UAPP(_ips_arr) { .path="", .m_f_dentry=NULL, \
	.ips_count=sizeof(_ips_arr)/sizeof(us_proc_ip_t), .p_ips=_ips_arr, \
	.vtps_count=0, .p_vtps=NULL, .loaded=0}
#define MY_ULIB(_lib, _ips_arr) { .path=#_lib, .m_f_dentry=NULL, \
	.ips_count=sizeof(_ips_arr)/sizeof(us_proc_ip_t), .p_ips=_ips_arr, \
	.vtps_count=0, .p_vtps=NULL, .loaded=0}
#define MY_UPROBE_ENTRY(_name, _entry_hand, _exit_hand) {.name = #_name, \
	.jprobe.entry = JPROBE_ENTRY(_entry_hand), \
	.retprobe.handler = (kretprobe_handler_t)_exit_hand}
#define MY_UPROBE_ENTRY_EXT(_name, _pre_entry_hand, _entry_hand, _exit_hand) {.name = #_name, .jprobe.pre_entry = (kprobe_pre_entry_handler_t)_pre_entry_hand, .jprobe.entry = JPROBE_ENTRY(_entry_hand), .retprobe.handler = (kretprobe_handler_t)_exit_hand}

#endif // __PROBES_H__
