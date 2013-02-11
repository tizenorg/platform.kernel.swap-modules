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

/* Detects when IPs are really loaded into phy mem and installs probes. */
extern void do_page_fault_j_pre_code(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
extern void do_page_fault_ret_pre_code (void);

/* Detects when target process exits. */
extern void do_exit_probe_pre_code (void);

/* Detects when target removes IPs. */
extern void do_munmap_probe_pre_code(struct mm_struct *mm, unsigned long start, size_t len);

/* Detects when target process removes IPs. */
extern void mm_release_probe_pre_code(void);

/* Delete uprobs in children at fork */
extern void copy_process_ret_pre_code(struct task_struct *p);

extern int us_proc_probes;
extern pid_t gl_nNotifyTgid;

enum {
	US_PROC_PF_INSTLD    = (1 << 0),
	US_PROC_CP_INSTLD    = (1 << 1),
	US_PROC_MR_INSTLD    = (1 << 2),
	US_PROC_EXIT_INSTLD  = (1 << 3),
	US_PROC_UNMAP_INSTLD = (1 << 4)
};

/* forward declarations */
struct task_struct;
struct pt_regs;
struct us_proc_ip_t;
struct us_ip;

/* Returns stack_size */
extern unsigned long get_stack_size(struct task_struct *task,
		struct pt_regs *regs);

/* Copies stack (or part of the stack) to the buffer */
extern unsigned long get_stack(struct task_struct *task, struct pt_regs *regs,
		char *buf, unsigned long sz);

/* Dumps given buffer to the trace */
extern int dump_to_trace(probe_id_t probe_id, void *addr, const char *buf,
		unsigned long sz);

/* Dumps stack to the trace */
extern int dump_backtrace(probe_id_t probe_id, struct task_struct *task,
		void *addr, struct pt_regs *regs, unsigned long sz);

/* Gets current function return address */
extern unsigned long get_ret_addr(struct task_struct *task, struct us_ip *ip);

extern unsigned long imi_sum_time;
extern unsigned long imi_sum_hit;

extern struct list_head proc_probes_list;

int register_usprobe(struct task_struct *task, struct us_ip *ip, int atomic);
int unregister_usprobe(struct task_struct *task, struct us_ip *ip, int atomic, int no_rp2);

#define user_backtrace(size) \
	do { \
		us_proc_ip_t *ip = __get_cpu_var(gpCurIp); \
		struct pt_regs *regs = __get_cpu_var(gpUserRegs); \
		dump_backtrace(US_PROBE_ID, current, ip->jprobe.kp.addr, regs, size); \
	} while (0)

struct dentry *dentry_by_path(const char *path);
int install_otg_ip(unsigned long addr,
			kprobe_pre_entry_handler_t pre_handler,
			unsigned long jp_handler,
			kretprobe_handler_t rp_handler);

#endif /* !defined(__US_PROC_INST_H__) */
