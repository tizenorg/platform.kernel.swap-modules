#ifndef __PRELOAD_PD_H__
#define __PRELOAD_PD_H__

struct pd_t;
struct hd_t;
struct sspt_proc;
struct dentry;
struct list_head;

/* process preload states */
enum ps_t {
	NOT_LOADED,
	LOADING,
	LOADED,
	FAILED,
	ERROR
};

struct pd_t *preload_pd_get(struct sspt_proc *proc);
unsigned long preload_pd_get_loader_base(struct pd_t *pd);
void preload_pd_set_loader_base(struct pd_t *pd, unsigned long vaddr);

struct hd_t *preload_pd_get_hd(struct pd_t *pd, struct dentry *dentry);
struct dentry *preload_pd_get_dentry(struct hd_t *hd);
struct pd_t *preload_pd_get_parent_pd(struct hd_t *hd);
enum ps_t preload_pd_get_state(struct hd_t *hd);
void preload_pd_set_state(struct hd_t *hd, enum ps_t state);
unsigned long preload_pd_get_handlers_base(struct hd_t *hd);
void preload_pd_set_handlers_base(struct hd_t *hd, unsigned long vaddr);
void *preload_pd_get_handle(struct hd_t *hd);
void preload_pd_set_handle(struct hd_t *hd, void __user *handle);
long preload_pd_get_attempts(struct hd_t *hd);
void preload_pd_dec_attempts(struct hd_t *hd);

char __user *preload_pd_get_path(struct pd_t *pd, struct hd_t *hd);

int preload_pd_init(void);
void preload_pd_uninit(void);


#endif /* __PRELOAD_PD_H__*/
