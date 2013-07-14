#ifndef _SWAP_MSG_H
#define _SWAP_MSG_H

#include <linux/types.h>

enum PROBE_TYPE {
	PT_US	= 1,
	PT_KS	= 3
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

void reset_discarded(void);
unsigned int get_discarded_count(void);
void reset_seq_num(void);

int proc_info_msg(struct task_struct *task, void *priv);
int sample_msg(struct pt_regs *regs);

int entry_event(const char *fmt, struct pt_regs *regs,
		 enum PROBE_TYPE pt, enum PROBE_SUB_TYPE pst);
int exit_event(struct pt_regs *regs);

int switch_entry(struct pt_regs *regs);
int switch_exit(struct pt_regs *regs);

int error_msg(const char *fmt, ...);

int us_msg(void *us_message);

#endif /* _SWAP_MSG_H */
