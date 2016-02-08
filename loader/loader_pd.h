#ifndef __LOADER_PD_H__
#define __LOADER_PD_H__

#include <loader/loader.h>

struct pd_t;
struct hd_t;
struct sspt_proc;
struct dentry;
struct list_head;

/* process loader states */
enum ps_t {
	NOT_LOADED,
	LOADING,
	LOADED,
	FAILED,
	ERROR
};

struct pd_t *lpd_get(struct sspt_proc *proc);
unsigned long lpd_get_loader_base(struct pd_t *pd);
void lpd_set_loader_base(struct pd_t *pd, unsigned long vaddr);

struct hd_t *lpd_get_hd(struct pd_t *pd, struct dentry *dentry);
struct dentry *lpd_get_dentry(struct hd_t *hd);
struct pd_t *lpd_get_parent_pd(struct hd_t *hd);
enum ps_t lpd_get_state(struct hd_t *hd);
void lpd_set_state(struct hd_t *hd, enum ps_t state);
unsigned long lpd_get_handlers_base(struct hd_t *hd);
void lpd_set_handlers_base(struct hd_t *hd, unsigned long vaddr);
void *lpd_get_handle(struct hd_t *hd);
void lpd_set_handle(struct hd_t *hd, void __user *handle);
long lpd_get_attempts(struct hd_t *hd);
void lpd_dec_attempts(struct hd_t *hd);

char __user *lpd_get_path(struct pd_t *pd, struct hd_t *hd);

int lpd_init(void);
void lpd_uninit(void);


#endif /* __LOADER_PD_H__*/
