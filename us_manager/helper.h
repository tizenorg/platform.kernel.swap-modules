#ifndef _HELPER_H
#define _HELPER_H

#include <linux/sched.h>

static inline int is_kthread(struct task_struct *task)
{
	return !task->mm;
}

int init_helper(void);
void uninit_helper(void);

int register_helper(void);
void unregister_helper(void);

#endif /* _HELPER_H */
