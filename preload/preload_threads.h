#ifndef __PRELOAD_THREADS_H__
#define __PRELOAD_THREADS_H__

struct task_struct;

int preload_threads_set_data(struct task_struct *task, unsigned long caller,
			     unsigned char call_type, unsigned long disable_addr);
int preload_threads_get_caller(struct task_struct *task, unsigned long *caller);
int preload_threads_get_call_type(struct task_struct *task,
				  unsigned char *call_type);
bool preload_threads_check_disabled_probe(struct task_struct *task,
					  unsigned long addr);
void preload_threads_enable_probe(struct task_struct *task, unsigned long addr);
int preload_threads_put_data(struct task_struct *task);
int preload_threads_init(void);
void preload_threads_exit(void);

#endif /* __PRELOAD_THREADS_H__ */
