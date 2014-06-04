#ifndef __PRELOAD_PD_H__
#define __PRELOAD_PD_H__

struct process_data;
struct task_struct;

/* process preload states */
enum preload_state_t {
	NOT_LOADED,
	LOADING,
	LOADED,
	FAILED,
    ERROR
};

//enum preload_state_t preload_pd_get_state(struct task_struct *task);
//void preload_pd_set_state(struct task_struct *task, enum preload_state_t state);
//unsigned long preload_pd_get_loader_base(struct task_struct *task);
//void preload_pd_set_loader_base(struct task_struct *task, unsigned long vaddr);
//unsigned long preload_pd_get_handlers_base(struct task_struct *task);
//void preload_pd_set_handlers_base(struct task_struct *task,
//                                  unsigned long vaddr);
////unsigned long preload_pd_get_flags(struct task_struct *task);
////void preload_pd_set_flags(struct task_struct *task, unsigned long flags);
//void *preload_pd_get_handle(struct task_struct *task);
//void preload_pd_set_handle(struct task_struct *task, void __user *handle);
//
//long preload_pd_get_attempts(struct task_struct *task);
//void preload_pd_dec_attempts(struct task_struct *task);
//
//void preload_pd_inc_refs(struct task_struct *task);
//void preload_pd_dec_refs(struct task_struct *task);
//long preload_pd_get_refs(struct task_struct *task);
//
//char __user *preload_pd_get_path(void);
//void preload_pd_put_path(struct task_struct *task);
//
//int preload_pd_create_pd(struct process_data **pd_pp, struct task_struct *task);


enum preload_state_t preload_pd_get_state(struct process_data *pd);
void preload_pd_set_state(struct process_data *pd, enum preload_state_t state);
unsigned long preload_pd_get_loader_base(struct process_data *pd);
void preload_pd_set_loader_base(struct process_data *pd, unsigned long vaddr);
unsigned long preload_pd_get_handlers_base(struct process_data *pd);
void preload_pd_set_handlers_base(struct process_data *pd, unsigned long vaddr);
void *preload_pd_get_handle(struct process_data *pd);
void preload_pd_set_handle(struct process_data *pd, void __user *handle);

long preload_pd_get_attempts(struct process_data *pd);
void preload_pd_dec_attempts(struct process_data *pd);

void preload_pd_inc_refs(struct process_data *pd);
void preload_pd_dec_refs(struct process_data *pd);
long preload_pd_get_refs(struct process_data *pd);

char __user *preload_pd_get_path(struct process_data *pd);
void preload_pd_put_path(struct process_data *pd);

int preload_pd_create_pd(void **target_place, struct task_struct *task);

int preload_pd_init(void);
void preload_pd_uninit(void);


#endif /* __PRELOAD_PD_H__*/
