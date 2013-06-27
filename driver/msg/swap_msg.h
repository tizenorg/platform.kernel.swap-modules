#ifndef _SWAP_MSG_H
#define _SWAP_MSG_H

#include <linux/types.h>

enum PROBE_TYPE {
	PT_US	= 1,
	PT_KS	= 2
};

enum PROBE_SUB_TYPE {
	PST_NONE	= 0,
	PST_KS_FILE	= 1,
	PST_KS_IPC	= 2,
	PST_KS_PROCESS	= 3,
	PST_KS_SIGNAL	= 4,
	PST_KS_NETWORK	= 5,
	PST_KS_DESK	= 6
};

struct pt_regs;

int init_msg(size_t buf_size);
void uninit_msg(void);

void proc_info_msg(struct task_struct *task);
void sample_msg(struct pt_regs *regs);

void entry_event(const char *fmt, struct pt_regs *regs,
		 enum PROBE_TYPE pt, enum PROBE_SUB_TYPE pst);
void exit_event(struct pt_regs *regs);

void switch_entry(struct pt_regs *regs);
void switch_exit(struct pt_regs *regs);

void error_msg(const char *fmt, ...);

#endif /* _SWAP_MSG_H */
