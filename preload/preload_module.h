#ifndef __PRELOAD_MODULE_H__
#define __PRELOAD_MODULE_H__

#include <linux/types.h>

struct dentry;
struct pd_t;
struct hd_t;
struct uretprobe;
struct uretprobe_instance;

bool preload_module_is_ready(void);
bool preload_module_is_running(void);
bool preload_module_is_not_ready(void);
void preload_module_set_ready(void);
void preload_module_set_running(void);
void preload_module_set_not_ready(void);


void preload_module_set_handler_dentry(struct dentry *dentry);

struct dentry *get_dentry(const char *filepath);
void put_dentry(struct dentry *dentry);

void preload_module_prepare_ujump(struct uretprobe_instance *ri,
				  struct pt_regs *regs, unsigned long addr);

unsigned long preload_not_loaded_entry(struct uretprobe_instance *ri,
				       struct pt_regs *regs, struct pd_t *pd,
				       struct hd_t *hd);
void preload_loading_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			 struct pd_t *pd, struct hd_t *hd);
void preload_failed_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			struct pd_t *pd, struct hd_t *hd);

void preload_set_rp_data_size(struct uretprobe *rp);
void preload_set_priv_origin(struct uretprobe_instance *ri, unsigned long addr);
unsigned long preload_get_priv_origin(struct uretprobe_instance *ri);


#endif /* __PRELOAD_MODULE_H__ */
