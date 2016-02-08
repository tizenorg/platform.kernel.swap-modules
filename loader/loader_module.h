#ifndef __LOADER_MODULE_H__
#define __LOADER_MODULE_H__

#include <linux/types.h>

struct dentry;
struct pd_t;
struct hd_t;
struct uretprobe;
struct uretprobe_instance;

bool loader_module_is_ready(void);
bool loader_module_is_running(void);
bool loader_module_is_not_ready(void);
void loader_module_set_ready(void);
void loader_module_set_running(void);
void loader_module_set_not_ready(void);

struct dentry *get_dentry(const char *filepath);
void put_dentry(struct dentry *dentry);

void loader_module_prepare_ujump(struct uretprobe_instance *ri,
				  struct pt_regs *regs, unsigned long addr);

unsigned long loader_not_loaded_entry(struct uretprobe_instance *ri,
				       struct pt_regs *regs, struct pd_t *pd,
				       struct hd_t *hd);
void loader_loading_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			 struct pd_t *pd, struct hd_t *hd);
void loader_failed_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			struct pd_t *pd, struct hd_t *hd);

void loader_set_rp_data_size(struct uretprobe *rp);
void loader_set_priv_origin(struct uretprobe_instance *ri, unsigned long addr);
unsigned long loader_get_priv_origin(struct uretprobe_instance *ri);
int loader_add_handler(char *path);


#endif /* __LOADER_MODULE_H__ */
