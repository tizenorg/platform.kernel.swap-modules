////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           us_proc_inst.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       us_proc_inst.c
//      AUTHOR:         A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.06.02
//      VERSION:        1.0
//      REVISION DATE:	2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

/*
    Functions in "us_proc_inst.h" file .
*/

#if !defined(__US_PROC_INST_H__)
#define __US_PROC_INST_H__

#include <linux/signal.h>	// struct sigpending
#include "sspt/ip.h"

/* Instruments or schedules pending instrumentation of user space process. */
extern int inst_usr_space_proc (void);
extern int deinst_usr_space_proc (void);

extern int us_proc_probes;
extern pid_t gl_nNotifyTgid;

/* forward declarations */
struct task_struct;
struct pt_regs;
struct us_proc_ip_t;
struct us_ip;

extern unsigned long imi_sum_time;
extern unsigned long imi_sum_hit;

extern struct list_head proc_probes_list;

int register_usprobe(struct task_struct *task, struct us_ip *ip, int atomic);
int unregister_usprobe(struct task_struct *task, struct us_ip *ip, int atomic);

struct dentry *dentry_by_path(const char *path);
int install_otg_ip(unsigned long addr,
			kprobe_pre_entry_handler_t pre_handler,
			unsigned long jp_handler,
			uretprobe_handler_t rp_handler);

#endif /* !defined(__US_PROC_INST_H__) */
