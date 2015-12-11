#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mman.h>
#include <linux/err.h>
#include <linux/types.h>
#include <kprobe/swap_kprobes.h>
#include <kprobe/swap_kprobes_deps.h>
#include <us_manager/sspt/sspt_proc.h>
#include <us_manager/sspt/ip.h>
#include <us_manager/callbacks.h>
#include <writer/kernel_operations.h>
#include <master/swap_initializer.h>
#include "preload.h"
#include "preload_probe.h"
#include "preload_debugfs.h"
#include "preload_module.h"
#include "preload_storage.h"
#include "preload_control.h"
#include "preload_threads.h"
#include "preload_pd.h"


struct us_priv {
	struct pt_regs regs;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long raddr;
	unsigned long origin;
};

static atomic_t dentry_balance = ATOMIC_INIT(0);

enum preload_status_t {
	SWAP_PRELOAD_NOT_READY = 0,
	SWAP_PRELOAD_READY = 1,
	SWAP_PRELOAD_RUNNING = 2
};

static enum preload_status_t __preload_status = SWAP_PRELOAD_NOT_READY;

static int __preload_cbs_start_h = -1;
static int __preload_cbs_stop_h = -1;


static struct dentry *__get_dentry(struct dentry *dentry)
{
	atomic_inc(&dentry_balance);
	return dget(dentry);
}



bool preload_module_is_running(void)
{
	if (__preload_status == SWAP_PRELOAD_RUNNING)
		return true;

	return false;
}

bool preload_module_is_ready(void)
{
	if (__preload_status == SWAP_PRELOAD_READY)
		return true;

	return false;
}

bool preload_module_is_not_ready(void)
{
	if (__preload_status == SWAP_PRELOAD_NOT_READY)
		return true;

	return false;
}

void preload_module_set_ready(void)
{
	__preload_status = SWAP_PRELOAD_READY;
}

void preload_module_set_running(void)
{
	__preload_status = SWAP_PRELOAD_RUNNING;
}

void preload_module_set_not_ready(void)
{
	__preload_status = SWAP_PRELOAD_NOT_READY;
}

struct dentry *get_dentry(const char *filepath)
{
	struct path path;
	struct dentry *dentry = NULL;

	if (kern_path(filepath, LOOKUP_FOLLOW, &path) == 0) {
		dentry = __get_dentry(path.dentry);
		path_put(&path);
	}

	return dentry;
}

void put_dentry(struct dentry *dentry)
{
	atomic_dec(&dentry_balance);
	dput(dentry);
}

static inline void __prepare_ujump(struct uretprobe_instance *ri,
				   struct pt_regs *regs,
				   unsigned long vaddr)
{
	ri->rp->up.ss_addr[smp_processor_id()] = (kprobe_opcode_t *)vaddr;

#ifdef CONFIG_ARM
	if (thumb_mode(regs)) {
		regs->ARM_cpsr &= ~PSR_T_BIT;
		ri->preload_thumb = 1;
	}
#endif /* CONFIG_ARM */
}

static inline int __push(struct pt_regs *regs, void *buf, size_t len)
{
	unsigned long sp = swap_get_stack_ptr(regs) - len;

	sp = PTR_ALIGN(sp, sizeof(unsigned long));
	if (copy_to_user((void __user *)sp, buf, len))
		return -EIO;
	swap_set_stack_ptr(regs, sp);

	return 0;
}

static inline void __save_uregs(struct uretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct us_priv *priv = (struct us_priv *)ri->data;

	memcpy(ri->data, regs, sizeof(*regs));
	priv->arg0 = swap_get_arg(regs, 0);
	priv->arg1 = swap_get_arg(regs, 1);
	priv->raddr = swap_get_ret_addr(regs);
}

static inline void __restore_uregs(struct uretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct us_priv *priv = (struct us_priv *)ri->data;

	memcpy(regs, ri->data, sizeof(*regs));
	swap_set_arg(regs, 0, priv->arg0);
	swap_set_arg(regs, 1, priv->arg1);
	swap_set_ret_addr(regs, priv->raddr);
#ifndef CONFIG_ARM
	/* need to do it only on x86 */
	regs->EREG(ip) -= 1;
#endif /* !CONFIG_ARM */
	/* we have just restored the registers => no need to do it in
	 * trampoline_uprobe_handler */
	ri->ret_addr = NULL;
}

static inline void print_regs(const char *prefix, struct pt_regs *regs,
			      struct uretprobe_instance *ri, struct hd_t *hd)
{
	struct dentry *dentry = preload_pd_get_dentry(hd);

#ifdef CONFIG_ARM
	printk(PRELOAD_PREFIX "%s[%d/%d] %s (%d) %s addr(%08lx), "
	       "r0(%08lx), r1(%08lx), r2(%08lx), r3(%08lx), "
	       "r4(%08lx), r5(%08lx), r6(%08lx), r7(%08lx), "
	       "sp(%08lx), lr(%08lx), pc(%08lx)\n",
	       current->comm, current->tgid, current->pid,
	       dentry != NULL ? (char *)(dentry->d_name.name) :
				(char *)("NULL"),
	       (int)preload_pd_get_state(hd),
	       prefix, (unsigned long)ri->rp->up.addr,
	       regs->ARM_r0, regs->ARM_r1, regs->ARM_r2, regs->ARM_r3,
	       regs->ARM_r4, regs->ARM_r5, regs->ARM_r6, regs->ARM_r7,
	       regs->ARM_sp, regs->ARM_lr, regs->ARM_pc);
#else /* !CONFIG_ARM */
	printk(PRELOAD_PREFIX "%s[%d/%d] %s (%d) %s addr(%08lx), "
	       "ip(%08lx), arg0(%08lx), arg1(%08lx), raddr(%08lx)\n",
	       current->comm, current->tgid, current->pid,
	       dentry != NULL ? (char *)(dentry->d_name.name) :
				(char *)("NULL"),
	       (int)preload_pd_get_state(hd),
	       prefix, (unsigned long)ri->rp->up.addr,
	       regs->EREG(ip), swap_get_arg(regs, 0), swap_get_arg(regs, 1),
	       swap_get_ret_addr(regs));
#endif /* CONFIG_ARM */
}

static inline unsigned long __get_r_debug_off(struct vm_area_struct *linker_vma)
{
	unsigned long start_addr;
	unsigned long offset = preload_debugfs_r_debug_offset();

	if (linker_vma == NULL)
		return 0;

	start_addr = linker_vma->vm_start;

	return (offset ? start_addr + offset : 0);
}

static struct vm_area_struct *__get_linker_vma(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct bin_info *ld_info;

	ld_info = preload_storage_get_linker_info();
	if (ld_info == NULL) {
		printk(PRELOAD_PREFIX "Cannot get linker info [%u %u %s]!\n",
		       task->tgid, task->pid, task->comm);
		return NULL;
	}

	for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file && vma->vm_flags & VM_EXEC
		    && vma->vm_file->f_dentry == ld_info->dentry) {
				preload_storage_put_linker_info(ld_info);
				return vma;
		}
	}

	preload_storage_put_linker_info(ld_info);
	return NULL;
}

static inline struct vm_area_struct *__get_vma_by_addr(struct task_struct *task,
						        unsigned long caller_addr)
{
	struct vm_area_struct *vma = NULL;

	if (task->mm == NULL)
		return NULL;
	vma = find_vma_intersection(task->mm, caller_addr, caller_addr + 1);

	return vma;
}









static bool __is_proc_mmap_mappable(struct task_struct *task)
{
	struct vm_area_struct *linker_vma = __get_linker_vma(task);
	struct sspt_proc *proc;
	unsigned long r_debug_addr;
	unsigned int state;
	enum { r_state_offset = sizeof(int) + sizeof(void *) + sizeof(long) };

	if (linker_vma == NULL)
		return false;

	r_debug_addr = __get_r_debug_off(linker_vma);
	if (r_debug_addr == 0)
		return false;

	r_debug_addr += r_state_offset;
	proc = sspt_proc_get_by_task(task);
	if (proc)
		proc->r_state_addr = r_debug_addr;

	if (get_user(state, (unsigned long *)r_debug_addr))
		return false;

	return !state;
}

static bool __should_we_preload_handlers(struct task_struct *task,
					 struct pt_regs *regs)
{
	unsigned long caller_addr = get_regs_ret_func(regs);
	struct vm_area_struct *cvma = __get_vma_by_addr(current, caller_addr);

	if (!__is_proc_mmap_mappable(task) ||
	    ((cvma != NULL) && (cvma->vm_file != NULL) &&
	    (cvma->vm_file->f_path.dentry != NULL) &&
	    preload_control_check_dentry_is_ignored(cvma->vm_file->f_path.dentry)))
		return false;

	return true;
}





struct mmap_priv {
	struct dentry *dentry;
};

static inline bool check_prot(unsigned long prot)
{
	return !!((prot & PROT_READ) && (prot & PROT_EXEC));
}

static int mmap_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct file *file = (struct file *)swap_get_karg(regs, 0);
	unsigned long prot = swap_get_karg(regs, 3);
	struct mmap_priv *priv = (struct mmap_priv *)ri->data;
	struct task_struct *task = current->group_leader;
	struct dentry *dentry, *loader_dentry;
	struct pd_t *pd;
	struct hd_t *hd;
	struct sspt_proc *proc;

	priv->dentry = NULL;
	if (!check_prot(prot))
		return 0;

	if (!file)
		return 0;

	dentry = file->f_dentry;
	if (dentry == NULL)
		return 0;

	loader_dentry = preload_debugfs_get_loader_dentry();
	if (dentry == loader_dentry) {
		priv->dentry = loader_dentry;
		return 0;
	}

	proc = sspt_proc_get_by_task(task);
	if (!proc)
		return 0;

	pd = preload_pd_get(proc);
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n",
		       __LINE__, current->tgid, current->comm);
		return 0;
	}

	hd = preload_pd_get_hd(pd, dentry);
	if (hd != NULL)
		priv->dentry = preload_pd_get_dentry(hd);

	return 0;
}

static int mmap_ret_handler(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct mmap_priv *priv = (struct mmap_priv *)ri->data;
	struct task_struct *task = current->group_leader;
	struct pd_t *pd;
	struct hd_t *hd;
	struct sspt_proc *proc;
	struct dentry *loader_dentry;
	unsigned long vaddr;

	if (!task->mm)
		return 0;

	if (priv->dentry == NULL)
		return 0;

	vaddr = (unsigned long)regs_return_value(regs);
	if (IS_ERR_VALUE(vaddr))
		return 0;

	proc = sspt_proc_get_by_task(task);
	if (!proc)
		return 0;

	pd = preload_pd_get(proc);
	if (pd == NULL) {
		printk(PRELOAD_PREFIX "%d: No process data! Current %d %s\n",
		       __LINE__, current->tgid, current->comm);
		return 0;
	}

	loader_dentry = preload_debugfs_get_loader_dentry();
	if (priv->dentry == loader_dentry)
		preload_pd_set_loader_base(pd, vaddr);


	hd = preload_pd_get_hd(pd, priv->dentry);
	if (hd != NULL)
		preload_pd_set_handlers_base(hd, vaddr);

	return 0;
}

static struct kretprobe mmap_rp = {
	.kp.symbol_name = "do_mmap_pgoff",
	.data_size = sizeof(struct mmap_priv),
	.entry_handler = mmap_entry_handler,
	.handler = mmap_ret_handler
};

static void preload_start_cb(void)
{
	int res;

	res = swap_register_kretprobe(&mmap_rp);
	if (res != 0)
		printk(KERN_ERR PRELOAD_PREFIX "Registering do_mmap_pgoff probe failed\n");
}

static void preload_stop_cb(void)
{
	swap_unregister_kretprobe(&mmap_rp);
}

static unsigned long __not_loaded_entry(struct uretprobe_instance *ri,
					struct pt_regs *regs,
					struct pd_t *pd, struct hd_t *hd)
{
	char __user *path = NULL;
	unsigned long vaddr = 0;
	unsigned long base;

	/* if linker is still doing its work, we do nothing */
	if (!__should_we_preload_handlers(current, regs))
		return 0;

	base = preload_pd_get_loader_base(pd);
	if (base == 0)
		return 0;   /* loader isn't mapped */

	/* jump to loader code if ready */
	vaddr = base + preload_debugfs_get_loader_offset();
	if (vaddr) {
		/* save original regs state */
		__save_uregs(ri, regs);
		print_regs("ORIG", regs, ri, hd);

		path = preload_pd_get_path(pd, hd);

		/* set dlopen args: filename, flags */
		swap_set_arg(regs, 0, (unsigned long)path/*swap_get_stack_ptr(regs)*/);
		swap_set_arg(regs, 1, 2 /* RTLD_NOW */);

		/* do the jump to dlopen */
		__prepare_ujump(ri, regs, vaddr);
		/* set new state */
		preload_pd_set_state(hd, LOADING);
	}

	return vaddr;
}

static void __loading_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			  struct pd_t *pd, struct hd_t *hd)
{
	struct us_priv *priv = (struct us_priv *)ri->data;
	unsigned long vaddr = 0;

	/* check if preloading has been completed */
	vaddr = preload_pd_get_loader_base(pd) +
		preload_debugfs_get_loader_offset();
	if (vaddr && (priv->origin == vaddr)) {
		preload_pd_set_handle(hd,
				      (void __user *)regs_return_value(regs));

		/* restore original regs state */
		__restore_uregs(ri, regs);
		print_regs("REST", regs, ri, hd);
		/* check if preloading done */

		if (preload_pd_get_handle(hd)) {
			preload_pd_set_state(hd, LOADED);
		} else {
			preload_pd_dec_attempts(hd);
			preload_pd_set_state(hd, FAILED);
		}
	}
}

static void __failed_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			 struct pd_t *pd, struct hd_t *hd)
{
	if (preload_pd_get_attempts(hd))
		preload_pd_set_state(hd, NOT_LOADED);
}



unsigned long preload_not_loaded_entry(struct uretprobe_instance *ri,
				       struct pt_regs *regs, struct pd_t *pd,
				       struct hd_t *hd)
{
	return __not_loaded_entry(ri, regs, pd, hd);
}

void preload_loading_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			 struct pd_t *pd, struct hd_t *hd)
{
	__loading_ret(ri, regs, pd, hd);
}

void preload_failed_ret(struct uretprobe_instance *ri, struct pt_regs *regs,
			struct pd_t *pd, struct hd_t *hd)
{
	__failed_ret(ri, regs, pd, hd);
}

void preload_module_prepare_ujump(struct uretprobe_instance *ri,
				  struct pt_regs *regs, unsigned long addr)
{
	__prepare_ujump(ri, regs, addr);
}

void preload_set_rp_data_size(struct uretprobe *rp)
{
	rp->data_size = sizeof(struct us_priv);
}

void preload_set_priv_origin(struct uretprobe_instance *ri, unsigned long addr)
{
	struct us_priv *priv = (struct us_priv *)ri->data;

	priv->origin = addr;
}

unsigned long preload_get_priv_origin(struct uretprobe_instance *ri)
{
	struct us_priv *priv = (struct us_priv *)ri->data;

    return priv->origin;
}


int preload_set(void)
{
	if (preload_module_is_running())
		return -EBUSY;

	return 0;
}

void preload_unset(void)
{
	swap_unregister_kretprobe(&mmap_rp);
	/*module_put(THIS_MODULE);*/
	preload_module_set_not_ready();

}


static int preload_module_init(void)
{
	int ret;

	ret = preload_debugfs_init();
	if (ret)
		goto out_err;

	ret = preload_storage_init();
	if (ret)
		goto exit_debugfs;

	ret = preload_pd_init();
	if (ret)
		goto exit_storage;

	/* TODO do not forget to remove set (it is just for debugging) */
	ret = preload_set();
	if (ret)
		goto exit_pd;

	ret = preload_control_init();
	if (ret)
		goto exit_set;

	ret = preload_threads_init();
	if (ret)
		goto exit_control;

	ret = register_preload_probes();
	if (ret)
		goto exit_threads;

	__preload_cbs_start_h = us_manager_reg_cb(START_CB, preload_start_cb);
	if (__preload_cbs_start_h < 0)
		goto exit_start_cb;

	__preload_cbs_stop_h = us_manager_reg_cb(STOP_CB, preload_stop_cb);
	if (__preload_cbs_stop_h < 0)
		goto exit_stop_cb;

	return 0;

exit_stop_cb:
	us_manager_unreg_cb(__preload_cbs_start_h);

exit_start_cb:
	unregister_preload_probes();

exit_threads:
	preload_threads_exit();

exit_control:
	preload_control_exit();

exit_set:
	preload_unset();

exit_pd:
	preload_pd_uninit();

exit_storage:
	preload_storage_exit();

exit_debugfs:
	preload_debugfs_exit();

out_err:
	return ret;
}

static void preload_module_exit(void)
{
	int balance;

	us_manager_unreg_cb(__preload_cbs_start_h);
	us_manager_unreg_cb(__preload_cbs_stop_h);
	unregister_preload_probes();
	preload_threads_exit();
	preload_control_exit();
	preload_unset();
	preload_pd_uninit();
	preload_storage_exit();
	preload_debugfs_exit();

	balance = atomic_read(&dentry_balance);
	atomic_set(&dentry_balance, 0);

	WARN(balance, "Bad GET/PUT dentry balance: %d\n", balance);
}

SWAP_LIGHT_INIT_MODULE(NULL, preload_module_init, preload_module_exit,
		       NULL, NULL);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP Preload Module");
MODULE_AUTHOR("Vasiliy Ulyanov <v.ulyanov@samsung.com>"
              "Alexander Aksenov <a.aksenov@samsung.com>");
