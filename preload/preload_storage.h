#ifndef __PRELOAD_STORAGE_H__
#define __PRELOAD_STORAGE_H__

struct list_head;
struct dentry;

struct bin_info {
	char *path;
	/* ghot */
	struct dentry *dentry;
};

struct bin_info_el {
	struct list_head list;
	char *path;
	/* ghot */
	struct dentry *dentry;
};


int preload_storage_set_handlers_info(char *path);
struct bin_info *preload_storage_get_handlers_info(void);
void preload_storage_put_handlers_info(struct bin_info *info);

int preload_storage_add_handler(char *path);
struct list_head *preload_storage_get_handlers(void);
void preload_storage_put_handlers(void);

int preload_storage_set_linker_info(char *path);
struct bin_info *preload_storage_get_linker_info(void);
void preload_storage_put_linker_info(struct bin_info *info);

int preload_storage_init(void);
void preload_storage_exit(void);

#endif /* __PRELOAD_HANDLERS_H__ */
