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

extern pid_t gl_nNotifyTgid;

/* forward declarations */
struct task_struct;
struct pt_regs;
struct us_proc_ip_t;
struct us_ip;
struct sspt_file;
struct sspt_page;
struct vm_area_struct;
enum US_FLAGS;

int is_libonly(void);
int is_us_instrumentation(void);

int register_usprobe(struct us_ip *ip);
int unregister_usprobe(struct us_ip *ip);

struct dentry *dentry_by_path(const char *path);
int install_otg_ip(unsigned long addr,
			kprobe_pre_entry_handler_t pre_handler,
			unsigned long jp_handler,
			uretprobe_handler_t rp_handler);


int check_install_pages_in_file(struct task_struct *task, struct sspt_file *file);
void install_proc_probes(struct task_struct *task, struct sspt_procs *procs);
pid_t find_proc_by_task(const struct task_struct *task, struct dentry *dentry);
void install_page_probes(unsigned long page_addr, struct task_struct *task, struct sspt_procs *procs);
int uninstall_us_proc_probes(struct task_struct *task, struct sspt_procs *procs, enum US_FLAGS flag);
int check_vma(struct vm_area_struct *vma);
int unregister_us_file_probes(struct task_struct *task, struct sspt_file *file, enum US_FLAGS flag);

#endif /* !defined(__US_PROC_INST_H__) */
