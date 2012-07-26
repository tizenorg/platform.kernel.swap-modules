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

/*
    Instruments or schedules pending instrumentation of user space process.
*/
extern int inst_usr_space_proc (void);
extern int deinst_usr_space_proc (void);

/*
    Detects when IPs are really loaded into phy mem and installs probes.
*/
extern void do_page_fault_ret_pre_code (void);
extern void  otg_probe_list_clean(char*);

/*
    Detects when target process exits and removes IPs.
*/
extern void do_exit_probe_pre_code (void);

/*
    Detects when target process is killed and removes IPs.
*/
//extern void send_sig_jprobe_event_handler (int sig, struct siginfo *info, struct task_struct *t, struct sigpending *signals);

extern int us_proc_probes;

extern pid_t gl_nNotifyTgid;

#define US_PROC_PF_INSTLD	0x1
#define US_PROC_EXIT_INSTLD	0x2
#define US_PROC_EXEC_INSTLD	0x4
#define US_PROC_FORK_INSTLD	0x8
//#define US_PROC_SS_INSTLD	0x4

#define MAX_STACK_SIZE 2*4096

/* forward declarations */
struct task_struct;
struct pt_regs;
struct us_proc_ip_t;

/* Returns stack_size */
static unsigned long get_stack_size(struct task_struct *task,
		struct pt_regs *regs);

/* Copies stack (or part of the stack) to the buffer */
static unsigned long get_stack(struct task_struct *task, struct pt_regs *regs,
		char *buf, unsigned long sz);

/* Dumps given buffer to the trace */
static int dump_to_trace(probe_id_t probe_id, void *addr, const char *buf,
		unsigned long sz);

/* Dumps stack to the trace */
static int dump_backtrace(probe_id_t probe_id, struct task_struct *task,
		void *addr, struct pt_regs *regs, unsigned long sz);

/* Gets current function return address */
static void *get_ret_addr(struct task_struct *task, us_proc_ip_t *ip,
		struct pt_regs *regs);

#define user_backtrace(size) \
	do { \
		us_proc_ip_t *ip = __get_cpu_var(gpCurIp); \
		struct pt_regs *regs = __get_cpu_var(gpUserRegs); \
		dump_backtrace(US_PROBE_ID, current, ip->jprobe.kp.addr, regs, size); \
	} while (0)

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif /* !defined(__US_PROC_INST_H__) */
