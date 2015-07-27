#include <linux/namei.h>
#include <us_manager/us_manager_common.h>
#include <us_manager/pf/pf_group.h>
#include <us_manager/sspt/sspt_page.h>
#include <us_manager/sspt/sspt_file.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/sspt/sspt_ip.h>
#include <us_manager/callbacks.h>
#include <us_manager/probes/probe_info_new.h>
#include <writer/kernel_operations.h>
#include <master/swap_initializer.h>
#include <writer/swap_msg.h>
#include <loader/loader.h>
#include "uihv.h"
#include "uihv_module.h"
#include "uihv_debugfs.h"

#define page_to_proc(page) ((page)->file->proc)
#define ip_to_proc(ip) page_to_proc((ip)->page)
#define urp_to_ip(rp) container_of(rp, struct sspt_ip, retprobe)

static struct dentry *uihv_dentry = NULL;

static inline struct pd_t *__get_process_data(struct uretprobe *rp)
{
	struct sspt_ip *ip = urp_to_ip(rp);
	struct sspt_proc *proc = ip_to_proc(ip);

	return lpd_get(proc);
}


/* ============================================================================
 * =                               ui_viewer                                  =
 * ============================================================================
 */

/* main handler for ui viewer */
static int uihv_main_eh(struct uretprobe_instance *ri, struct pt_regs *regs);
static int uihv_main_rh(struct uretprobe_instance *ri, struct pt_regs *regs);
static struct probe_desc pin_main = MAKE_URPROBE(uihv_main_eh,
						     uihv_main_rh, 0);

struct ui_viewer_data {
	struct dentry *app_dentry;
	struct probe_new p_main;
	struct pf_group *pfg;
};

static struct ui_viewer_data __ui_data;

static int uihv_data_inst(void)
{
	int ret;
	struct pf_group *pfg;

	pfg = get_pf_group_by_dentry(__ui_data.app_dentry,
				     (void *)__ui_data.app_dentry);
	if (pfg == NULL)
		return -ENOMEM;

	ret = pin_register(&__ui_data.p_main, pfg, __ui_data.app_dentry);
	if (ret)
		goto put_g;

	__ui_data.pfg = pfg;

	return 0;
put_g:
	put_pf_group(pfg);
	return ret;
}



struct dentry *get_dentry(const char *filepath)
{
	struct path path;
	struct dentry *dentry = NULL;

	if (kern_path(filepath, LOOKUP_FOLLOW, &path) == 0) {
		dentry = dget(path.dentry);
		path_put(&path);
	}

	return dentry;
}

void put_dentry(struct dentry *dentry)
{
	dput(dentry);
}

int uihv_data_set(const char *app_path, unsigned long main_addr)
{
	struct dentry *dentry;

	dentry = dentry_by_path(app_path);
	if (dentry == NULL)
		return -ENOENT;

	__ui_data.app_dentry = dentry;
	__ui_data.p_main.desc = &pin_main;
	__ui_data.p_main.offset = main_addr;
	__ui_data.pfg = NULL;

	return uihv_data_inst();
}

int uihv_set_handler(char *path)
{
	struct dentry *dentry;
	int ret;

	if (uihv_dentry != NULL)
		put_dentry(uihv_dentry);

	dentry = get_dentry(path);
	if (dentry == NULL) {
		printk(KERN_WARNING UIHV_PREFIX "Error! Cannot get handler %s\n",
			   path);
		return -EINVAL;
	}

	ret = loader_add_handler(path);
	if (ret != 0)
		return ret;

	uihv_dentry = dentry;

	return 0;
}



/* ============================================================================
 * =                          ui viewer handlers                              =
 * ============================================================================
 */
static int uihv_main_eh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct pd_t *pd = __get_process_data(ri->rp);
	struct hd_t *hd;
	unsigned long old_pc = swap_get_instr_ptr(regs);
	unsigned long vaddr = 0;

	if (uihv_dentry == NULL)
		return 0;

	hd = lpd_get_hd(pd, uihv_dentry);
	if (hd == NULL)
		return 0;

	if (lpd_get_state(hd) == NOT_LOADED)
		vaddr = loader_not_loaded_entry(ri, regs, pd, hd);

	loader_set_priv_origin(ri, vaddr);

	/* PC change check */
	return old_pc != swap_get_instr_ptr(regs);
}

static int uihv_main_rh(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct pd_t *pd = __get_process_data(ri->rp);
	struct hd_t *hd;

	if (uihv_dentry == NULL)
		return 0;

	hd = lpd_get_hd(pd, uihv_dentry);
	if (hd == NULL)
		return 0;

	if (lpd_get_state(hd) == LOADING)
		loader_loading_ret(ri, regs, pd, hd);

	return 0;
}

static int uihv_init(void)
{
	int ret;

	ret = uihv_dfs_init();

	return ret;
}

static void uihv_exit(void)
{
	if (uihv_dentry != NULL)
		put_dentry(uihv_dentry);
}

SWAP_LIGHT_INIT_MODULE(NULL, uihv_init, uihv_exit, NULL, NULL);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP UI Hierarchy Viewer");
MODULE_AUTHOR("Alexander Aksenov <a.aksenov@samsung.com>, Anastasia Lypa");
