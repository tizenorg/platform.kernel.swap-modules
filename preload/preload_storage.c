#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <ks_features/ks_map.h>
#include "preload.h"
#include "preload_module.h"
#include "preload_storage.h"

static struct bin_info __handlers_info = { NULL, NULL };
static struct bin_info __linker_info = { NULL, NULL };

static LIST_HEAD(handlers_list);

static inline struct bin_info *__get_handlers_info(void)
{
	return &__handlers_info;
}

static inline bool __check_handlers_info(void)
{
	return (__handlers_info.dentry != NULL); /* TODO */
}

static inline int __add_handler(char *path)
{
	struct dentry *dentry;
	size_t len = strnlen(path, PATH_MAX);
	struct bin_info_el *bin;
	int ret = 0;

	bin = kmalloc(sizeof(*bin), GFP_KERNEL);
	if (bin == NULL) {
		ret = -ENOMEM;
		goto add_handler_fail;
	}

	bin->path = kmalloc(len + 1, GFP_KERNEL);
	if (bin->path == NULL) {
		ret = -ENOMEM;
		goto add_handler_fail_free_bin;
	}

	dentry = get_dentry(path);
	if (!dentry) {
		ret = -ENOENT;
		goto add_handler_fail_free_path;
	}

	INIT_LIST_HEAD(&bin->list);
	strncpy(bin->path, path, len);
	bin->path[len] = '\0';
	bin->dentry = dentry;
	list_add_tail(&bin->list, &handlers_list);

	return ret;

add_handler_fail_free_path:
	kfree(bin->path);

add_handler_fail_free_bin:
	kfree(bin);

add_handler_fail:
	return ret;
}

static inline void __remove_handler(struct bin_info_el *bin)
{
	list_del(&bin->list);
	put_dentry(bin->dentry);
	kfree(bin->path);
	kfree(bin);
}

static inline void __remove_handlers(void)
{
	struct bin_info_el *bin, *tmp;

	list_for_each_entry_safe(bin, tmp, &handlers_list, list)
		__remove_handler(bin);
}

static inline int __init_handlers_info(char *path)
{
	struct dentry *dentry;
	size_t len = strnlen(path, PATH_MAX);
	int ret = 0;

	__handlers_info.path = kmalloc(len + 1, GFP_KERNEL);
	if (__handlers_info.path == NULL) {
		ret = -ENOMEM;
		goto init_handlers_fail;
	}

	dentry = get_dentry(path);
	if (!dentry) {
		ret = -ENOENT;
		goto init_handlers_fail_free;
	}

	strncpy(__handlers_info.path, path, len);
	__handlers_info.path[len] = '\0';
	__handlers_info.dentry = dentry;

	return ret;

init_handlers_fail_free:
	kfree(__handlers_info.path);

init_handlers_fail:
	return ret;
}

static inline void __drop_handlers_info(void)
{
	kfree(__handlers_info.path);
	__handlers_info.path = NULL;

	if (__handlers_info.dentry)
		put_dentry(__handlers_info.dentry);
	__handlers_info.dentry = NULL;
}

static inline struct bin_info *__get_linker_info(void)
{
	return &__linker_info;
}

static inline bool __check_linker_info(void)
{
	return (__linker_info.dentry != NULL); /* TODO */
}

static inline int __init_linker_info(char *path)
{
	struct dentry *dentry;
	size_t len = strnlen(path, PATH_MAX);
	int ret = 0;


	__linker_info.path = kmalloc(len + 1, GFP_KERNEL);
	if (__linker_info.path == NULL) {
		ret = -ENOMEM;
		goto init_linker_fail;
	}

	dentry = get_dentry(path);
	if (!dentry) {
		ret = -ENOENT;
		goto init_linker_fail_free;
	}

	strncpy(__linker_info.path, path, len);
	__linker_info.path[len] = '\0';
	__linker_info.dentry = dentry;

	return ret;

init_linker_fail_free:
	kfree(__linker_info.path);

init_linker_fail:

	return ret;
}

static inline void __drop_linker_info(void)
{
	kfree(__linker_info.path);
	__linker_info.path = NULL;

	if (__linker_info.dentry)
		put_dentry(__linker_info.dentry);
	__linker_info.dentry = NULL;
}




int preload_storage_set_handlers_info(char *path)
{
	int ret;

	ret = __init_handlers_info(path);
	if (ret != 0)
		return ret;

	ret = __add_handler(path);
	if (ret != 0)
		return ret;

	preload_module_set_handler_dentry(__handlers_info.dentry);

	return ret;
}

int preload_storage_add_handler(char *path)
{
	int ret;

	ret = __add_handler(path);
	if (ret != 0)
		return ret;

	return ret;
}

struct bin_info *preload_storage_get_handlers_info(void)
{
	struct bin_info *info = __get_handlers_info();

	if (__check_handlers_info())
		return info;

	return NULL;
}

struct list_head *preload_storage_get_handlers(void)
{
	/* TODO counter, syncs */
	return &handlers_list;
}

void preload_storage_put_handlers_info(struct bin_info *info)
{
}

void preload_storage_put_handlers(void)
{
	/* TODO dec counter, release sync */
}

int preload_storage_set_linker_info(char *path)
{
	return __init_linker_info(path);
}

struct bin_info *preload_storage_get_linker_info(void)
{
	struct bin_info *info = __get_linker_info();

	if (__check_linker_info())
		return info;

	return NULL;
}

void preload_storage_put_linker_info(struct bin_info *info)
{
}

int preload_storage_init(void)
{
	return 0;
}

void preload_storage_exit(void)
{
	__drop_handlers_info();
	__drop_linker_info();
	__remove_handlers();
}
