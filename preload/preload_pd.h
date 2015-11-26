#ifndef __PRELOAD_PD_H__
#define __PRELOAD_PD_H__

struct pd_t;
struct sspt_proc;

/* process preload states */
enum ps_t {
	NOT_LOADED,
	LOADING,
	LOADED,
	FAILED,
	ERROR
};

struct pd_t *preload_pd_get(struct sspt_proc *proc);

enum ps_t preload_pd_get_state(struct pd_t *pd);
void preload_pd_set_state(struct pd_t *pd, enum ps_t state);
unsigned long preload_pd_get_loader_base(struct pd_t *pd);
void preload_pd_set_loader_base(struct pd_t *pd, unsigned long vaddr);
unsigned long preload_pd_get_handlers_base(struct pd_t *pd);
void preload_pd_set_handlers_base(struct pd_t *pd, unsigned long vaddr);
void *preload_pd_get_handle(struct pd_t *pd);
void preload_pd_set_handle(struct pd_t *pd, void __user *handle);

long preload_pd_get_attempts(struct pd_t *pd);
void preload_pd_dec_attempts(struct pd_t *pd);

char __user *preload_pd_get_path(struct pd_t *pd);

int preload_pd_init(void);
void preload_pd_uninit(void);


#endif /* __PRELOAD_PD_H__*/
