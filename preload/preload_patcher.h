#ifndef __PRELOAD_PATCHER_H__
#define __PRELOAD_PATCHER_H__

struct task_struct;

int preload_patcher_patch_proc(void *addr, unsigned long val,
			        struct task_struct *task);
int preload_patcher_write_string(void *addr, char *string, size_t len,
				  struct task_struct *task);
int preload_patcher_get_ul(void *addr, unsigned long *val,
			    struct task_struct *task);
int preload_patcher_null_mem(void *addr, int size, struct task_struct *task);
int preload_patcher_get_ui(void *addr, unsigned int *val,
			    struct task_struct *task);



#endif /* __PRELOAD_PATCHER_H__ */
