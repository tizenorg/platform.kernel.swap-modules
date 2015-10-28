#include <linux/slab.h>
#include <kprobe/swap_kprobes_deps.h>
#include <writer/kernel_operations.h>
#include <writer/swap_msg.h>
#include <us_manager/sspt/ip.h>
#include <us_manager/sspt/sspt_page.h>
#include <us_manager/sspt/sspt_file.h>
#include "preload.h"
#include "preload_pd.h"
#include "preload_control.h"
#include "preload_threads.h"
#include "preload_module.h"

#define page_to_proc(page) ((page)->file->proc)
#define ip_to_proc(ip) page_to_proc((ip)->page)

enum {
	/* task preload flags */
	HANDLER_RUNNING = 0x1
};

static struct dentry *handler_dentry = NULL;


static inline struct pd_t *__get_process_data(struct uretprobe *rp)
{
	struct us_ip *ip = to_us_ip(rp);
	struct sspt_proc *proc = ip_to_proc(ip);

	return preload_pd_get(proc);
}

static inline struct vm_area_struct *__get_vma_by_addr(struct task_struct *task,
						       unsigned long caddr)
{
	struct vm_area_struct *vma = NULL;

	if ((task == NULL) || (task->mm == NULL))
		return NULL;
	vma = find_vma_intersection(task->mm, caddr, caddr + 1);

	return vma;
}

static inline bool __is_probe_non_block(struct us_ip *ip)
{
	if (ip->desc->info.pl_i.flags & SWAP_PRELOAD_NON_BLOCK_PROBE)
		return true;

	return false;
}

static inline bool __inverted(struct us_ip *ip)
{
	unsigned long flags = ip->desc->info.pl_i.flags;

	if (flags & SWAP_PRELOAD_INVERTED_PROBE)
		return true;

	return false;
}

static inline bool __check_flag_and_call_type(struct us_ip *ip,
					      enum preload_call_type ct)
{
	bool inverted = __inverted(ip);

	if (ct != NOT_INSTRUMENTED || inverted)
		return true;

	return false;
}

static inline bool __is_handlers_call(struct vm_area_struct *caller,
				      struct pd_t *pd)
{
	struct hd_t *hd;

	if (caller == NULL || caller->vm_file == NULL ||
	    caller->vm_file->f_path.dentry == NULL) {
		return false;
	}

	hd = preload_pd_get_hd(pd, caller->vm_file->f_path.dentry);
	if (hd != NULL)
		return true;

	return false;
}

static inline bool __should_drop(struct us_ip *ip, enum preload_call_type ct)
{
	if (ct == NOT_INSTRUMENTED)
		return true;

	return false;
}

static inline int __msg_sanitization(char *user_msg, size_t len,
				     char *call_type_p, char *caller_p)
{
	if ((call_type_p < user_msg) || (call_type_p > user_msg + len) ||
	    (caller_p < user_msg) || (caller_p > user_msg + len))
		return -EINVAL;

	return 0;
}




static unsigned long __do_preload_entry(struct uretprobe_instance *ri,
					struct pt_regs *regs,
					struct hd_t *hd)
{
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	unsigned long offset = ip->desc->info.pl_i.handler;
	unsigned long vaddr = 0;
	unsigned long base;
	unsigned long disable_addr;
	unsigned long caddr;
	struct vm_area_struct *cvma;
	enum preload_call_type ct;

	base = preload_pd_get_handlers_base(hd);
	if (base == 0)
		return 0;	/* handlers isn't mapped */

	/* jump to preloaded handler */
	vaddr = base + offset;
	if (vaddr) {
		caddr = get_regs_ret_func(regs);
		cvma = __get_vma_by_addr(current, caddr);
		ct = preload_control_call_type(ip, (void *)caddr);
		disable_addr = __is_probe_non_block(ip) ? ip->orig_addr : 0;

		/* jump only if caller is instumented and it is not a system lib -
		 * this leads to some errors */
		if (cvma != NULL && cvma->vm_file != NULL &&
			cvma->vm_file->f_path.dentry != NULL) {

			struct dentry *dentry = cvma->vm_file->f_path.dentry;
			struct pd_t *pd = preload_pd_get_parent_pd(hd);

			if (!preload_control_check_dentry_is_ignored(dentry) &&
			    __check_flag_and_call_type(ip, ct) &&
			    !__is_handlers_call(cvma, pd)) {

				bool drop = __should_drop(ip, ct);
				if (preload_threads_set_data(current, caddr,
							     ct, disable_addr,
							     drop) != 0)
					printk(PRELOAD_PREFIX "Error! Failed "
					       "to set caller 0x%lx for "
					       "%d/%d\n", caddr,
					       current->tgid,
					       current->pid);
				/* args are not changed */
				preload_module_prepare_ujump(ri, regs, vaddr);
				if (disable_addr == 0)
					set_preload_flags(current,
							  HANDLER_RUNNING);
			}
		}
	}

	return vaddr;
}

static int preload_us_entry(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct pd_t *pd = __get_process_data(ri->rp);
	struct hd_t *hd;
	unsigned long old_pc = swap_get_instr_ptr(regs);
	unsigned long flags = get_preload_flags(current);
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	unsigned long vaddr = 0;

	if (handler_dentry == NULL)
		goto out_set_orig;

	if ((flags & HANDLER_RUNNING) ||
	    preload_threads_check_disabled_probe(current, ip->orig_addr))
		goto out_set_orig;

	hd = preload_pd_get_hd(pd, handler_dentry);
	if (hd == NULL)
		goto out_set_orig;

	if ((flags & HANDLER_RUNNING) ||
		preload_threads_check_disabled_probe(current, ip->orig_addr))
		goto out_set_orig;

	if (preload_pd_get_state(hd) == NOT_LOADED ||
	    preload_pd_get_state(hd) == FAILED)
		vaddr = preload_not_loaded_entry(ri, regs, pd, hd);
	else if (preload_pd_get_state(hd) == LOADED)
		vaddr =__do_preload_entry(ri, regs, hd);

out_set_orig:
	preload_set_priv_origin(ri, vaddr);

	/* PC change check */
	return old_pc != swap_get_instr_ptr(regs);
}

static void __do_preload_ret(struct uretprobe_instance *ri, struct hd_t *hd)
{
	struct us_ip *ip = container_of(ri->rp, struct us_ip, retprobe);
	unsigned long flags = get_preload_flags(current);
	unsigned long offset = ip->desc->info.pl_i.handler;
	unsigned long vaddr = 0;

	if ((flags & HANDLER_RUNNING) ||
	    preload_threads_check_disabled_probe(current, ip->orig_addr)) {
		bool non_blk_probe = __is_probe_non_block(ip);

		/* drop the flag if the handler has completed */
		vaddr = preload_pd_get_handlers_base(hd) + offset;
		if (vaddr && (preload_get_priv_origin(ri) == vaddr)) {
			if (preload_threads_put_data(current) != 0)
				printk(PRELOAD_PREFIX "Error! Failed to put "
				       "caller slot for %d/%d\n", current->tgid,
				       current->pid);
			if (!non_blk_probe) {
				flags &= ~HANDLER_RUNNING;
				set_preload_flags(current, flags);
			}
		}
	}
}

static int preload_us_ret(struct uretprobe_instance *ri, struct pt_regs *regs)
{
	struct pd_t *pd = __get_process_data(ri->rp);
	struct hd_t *hd;

	if (handler_dentry == NULL)
		return 0;

	hd = preload_pd_get_hd(pd, handler_dentry);
	if (hd == NULL)
		return 0;

	switch (preload_pd_get_state(hd)) {
	case NOT_LOADED:
		/* loader has not yet been mapped... just ignore */
		break;
	case LOADING:
		preload_loading_ret(ri, regs, pd, hd);
		break;
	case LOADED:
		__do_preload_ret(ri, hd);
		break;
	case FAILED:
		preload_failed_ret(ri, regs, pd, hd);
		break;
	case ERROR:
	default:
		break;
	}

	return 0;
}





static void __write_data_to_msg(char *msg, size_t len,
				unsigned long call_type_off,
				unsigned long caller_off,
				unsigned long caller_addr)
{
	unsigned char call_type = 0;
	unsigned long caller = 0;
	int ret;

	if (caller_addr != 0) {
		caller = caller_addr;
		call_type =
		    preload_control_call_type_always_inst((void *)caller);
	} else {
		ret = preload_threads_get_caller(current, &caller);
		if (ret != 0) {
			caller = 0xbadbeef;
			printk(PRELOAD_PREFIX "Error! Cannot get caller address"
			       " for %d/%d\n", current->tgid, current->pid);
		}

		ret = preload_threads_get_call_type(current, &call_type);
		if (ret != 0) {
			call_type = 0xff;
			printk(PRELOAD_PREFIX "Error! Cannot get call type for "
			       "%d/%d\n", current->tgid, current->pid);
		}
	}

	/* Using the same types as in the library. */
	*(uint32_t *)(msg + call_type_off) = (uint32_t)call_type;
	*(uintptr_t *)(msg + caller_off) = (uintptr_t)caller;
}

static int write_msg_handler(struct uprobe *p, struct pt_regs *regs)
{
	char *user_buf;
	char *buf;
	char *caller_p;
	char *call_type_p;
	size_t len;
	unsigned long caller_offset;
	unsigned long call_type_offset;
	unsigned long caller_addr;
	int ret;

	/* FIXME: swap_get_uarg uses get_user(), it might sleep */
	user_buf = (char *)swap_get_uarg(regs, 0);
	len = swap_get_uarg(regs, 1);
	call_type_p = (char *)swap_get_uarg(regs, 2);
	caller_p = (char *)swap_get_uarg(regs, 3);
	caller_addr = swap_get_uarg(regs, 4);

	ret = __msg_sanitization(user_buf, len, call_type_p, caller_p);
	if (ret != 0) {
		printk(PRELOAD_PREFIX "Invalid message pointers!\n");
		return 0;
	}

	ret = preload_threads_get_drop(current);
	if (ret > 0)
		return 0;

	buf = kmalloc(len, GFP_ATOMIC);
	if (buf == NULL) {
		printk(PRELOAD_PREFIX "No mem for buffer! Size = %d\n", len);
		return 0;
	}

	ret = read_proc_vm_atomic(current, (unsigned long)user_buf, buf, len);
	if (ret < 0) {
		printk(PRELOAD_PREFIX "Cannot copy data from userspace! Size = "
				      "%d ptr 0x%lx ret %d\n", len,
				      (unsigned long)user_buf, ret);
		goto write_msg_fail;
	}

	/* Evaluating call_type and caller offset in message:
	 * data offset = data pointer - beginning of the message.
	 */
	call_type_offset = (unsigned long)(call_type_p - user_buf);
	caller_offset = (unsigned long)(caller_p - user_buf);

	__write_data_to_msg(buf, len, call_type_offset, caller_offset,
			    caller_addr);

	ret = swap_msg_raw(buf, len);
	if (ret != len)
		printk(PRELOAD_PREFIX "Error writing probe lib message\n");

write_msg_fail:
	kfree(buf);

	return 0;
}









static int get_caller_handler(struct uprobe *p, struct pt_regs *regs)
{
	unsigned long caller;
	int ret;

	ret = preload_threads_get_caller(current, &caller);
	if (ret != 0) {
		caller = 0xbadbeef;
		printk(PRELOAD_PREFIX "Error! Cannot get caller address for "
		       "%d/%d\n", current->tgid, current->pid);
	}

	swap_put_uarg(regs, 0, caller);

	return 0;
}

static int get_call_type_handler(struct uprobe *p, struct pt_regs *regs)
{
	unsigned char call_type;
	int ret;

	ret = preload_threads_get_call_type(current, &call_type);
	if (ret != 0) {
		call_type = 0xff;
		printk(PRELOAD_PREFIX "Error! Cannot get call type for %d/%d\n",
		       current->tgid, current->pid);
	}

	swap_put_uarg(regs, 0, call_type);

	return 0;
}






int ph_get_caller_init(struct us_ip *ip)
{
	struct uprobe *up = &ip->uprobe;

	up->pre_handler = get_caller_handler;

	return 0;
}

void ph_get_caller_exit(struct us_ip *ip)
{
}

int ph_get_call_type_init(struct us_ip *ip)
{
	struct uprobe *up = &ip->uprobe;

	up->pre_handler = get_call_type_handler;

	return 0;
}

void ph_get_call_type_exit(struct us_ip *ip)
{
}

int ph_write_msg_init(struct us_ip *ip)
{
	struct uprobe *up = &ip->uprobe;

	up->pre_handler = write_msg_handler;

	return 0;
}

void ph_write_msg_exit(struct us_ip *ip)
{
}

void ph_set_handler_dentry(struct dentry *dentry)
{
	handler_dentry = dentry;
}


int ph_uprobe_init(struct us_ip *ip)
{
	struct uretprobe *rp = &ip->retprobe;

	rp->entry_handler = preload_us_entry;
	rp->handler = preload_us_ret;
	/* FIXME actually additional data_size is needed only when we jump
	 * to dlopen */
	preload_set_rp_data_size(rp);

	return 0;
}

void ph_uprobe_exit(struct us_ip *ip)
{
}
