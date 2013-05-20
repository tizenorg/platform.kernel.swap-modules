////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           us_proc_inst.c
//
//      DESCRIPTION:
//      This file is C source for SWAP driver.
//
//      SEE ALSO:       us_proc_inst.h
//      AUTHOR:         A.Gerenkov, E. Gorelkina
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.06.02
//      VERSION:        1.0
//      REVISION DATE:  2008.12.02
//
////////////////////////////////////////////////////////////////////////////////////

#include "module.h"
#include "us_proc_inst.h"

#include "../kprobe/dbi_kprobes_deps.h"
#include "../uprobe/swap_uprobes.h"

#include "sspt/sspt.h"
#include "filters/filters_core.h"
#include "filters/filter_by_pach.h"
#include "helper.h"
#include "us_slot_manager.h"

static const char *app_filter = "app";

#define print_event(fmt, args...) 						\
{ 										\
	char *buf[1024];							\
	sprintf(buf, fmt, ##args);						\
	pack_event_info(US_PROBE_ID, RECORD_ENTRY, "ds", 0x0badc0de, buf);	\
}

// is user-space instrumentation
int is_us_instrumentation(void)
{
	return !!us_proc_info.path;
}

struct dentry *dentry_by_path(const char *path)
{
	struct dentry *dentry;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	struct path st_path;
	if (kern_path(path, LOOKUP_FOLLOW, &st_path) != 0) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	struct nameidata nd;
	if (path_lookup(path, LOOKUP_FOLLOW, &nd) != 0) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
		EPRINTF("failed to lookup dentry for path %s!", path);
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	dentry = nd.dentry;
	path_release(&nd);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
	dentry = nd.path.dentry;
	path_put(&nd.path);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	dentry = st_path.dentry;
	path_put(&st_path);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25) */
	return dentry;
}

int check_vma(struct vm_area_struct *vma)
{
	return vma->vm_file && !(vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_ACCOUNT) ||
			!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) ||
			!(vma->vm_flags & (VM_READ | VM_MAYREAD)));
}

int install_otg_ip(unsigned long addr,
			kprobe_pre_entry_handler_t pre_handler,
			unsigned long jp_handler,
			uretprobe_handler_t rp_handler)
{
	int ret = 0;
	struct task_struct *task = current->group_leader;
	struct mm_struct *mm = task->mm;

	if (mm) {
		struct vm_area_struct *vma = find_vma(mm, addr);
		if (vma && (vma->vm_flags & VM_EXEC) &&
		    vma->vm_file && vma->vm_file->f_dentry) {
			unsigned long offset_addr = addr - vma->vm_start;
			struct dentry *dentry = vma->vm_file->f_dentry;
			char *name = dentry->d_iname;
			struct sspt_proc *proc = sspt_proc_get_by_task(task);
			struct ip_data pd = {
					.offset = offset_addr,
					.pre_handler = pre_handler,
					.jp_handler = jp_handler,
					.rp_handler = rp_handler,
					.flag_retprobe = 1
			};

			struct sspt_file *file = sspt_proc_find_file_or_new(proc, dentry, name);
			struct sspt_page *page = sspt_get_page(file, offset_addr);
			struct us_ip *ip = sspt_find_ip(page, offset_addr & ~PAGE_MASK);

			if (!file->loaded) {
				sspt_file_set_mapping(file, vma);
				file->loaded = 1;
			}

			if (ip == NULL) {
				// TODO: sspt_proc_find_file_or_new --> sspt_proc_find_file ?!
				struct sspt_file *file = sspt_proc_find_file_or_new(proc, dentry, name);
				sspt_file_add_ip(file, &pd);

				/* if addr mapping, that probe install, else it be installed in do_page_fault handler */
				if (page_present(mm, addr)) {
					ip = sspt_find_ip(page, offset_addr & ~PAGE_MASK);
					sspt_set_ip_addr(ip, page, file);

					// TODO: error
					ret = sspt_register_usprobe(ip);
					if (ret == 0) {
						sspt_page_installed(page);
					} else {
						printk("ERROR install_otg_ip: ret=%d\n", ret);
					}
				}
			}

			sspt_put_page(page);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(install_otg_ip);

int deinst_usr_space_proc (void)
{
	int iRet = 0, found = 0;
	struct task_struct *task = NULL;
	struct sspt_proc *proc;

	if (!is_us_instrumentation()) {
		return 0;
	}

	unregister_helper();

	if (iRet)
		EPRINTF ("uninstall_kernel_probe(do_munmap) result=%d!", iRet);


	for_each_process(task) {
		proc = sspt_proc_get_by_task(task);
		if (proc) {
			int ret = sspt_proc_uninstall(proc, task, US_UNREGS_PROBE);
			if (ret) {
				EPRINTF ("failed to uninstall IPs (%d)!", ret);
			}

			dbi_unregister_all_uprobes(task);
		}
	}

	uninit_filter();
	unregister_filter(app_filter);

	return iRet;
}

int inst_usr_space_proc (void)
{
	int ret, i;
	struct task_struct *task = NULL, *ts;
	struct sspt_proc *proc;

	if (!is_us_instrumentation()) {
		return 0;
	}

	DPRINTF("User space instr");

	ret = register_filter(app_filter, get_filter_by_pach());
	if (ret)
		return ret;

	if (strcmp(us_proc_info.path, "*")) {
		ret = set_filter(app_filter);
		if (ret)
			return ret;

		ret = init_filter(us_proc_info.m_f_dentry, 0);
		if (ret)
			return ret;
	}

	ret = register_helper();
	if (ret) {
		return ret;
	}

	for_each_process(task) {
		ts = check_task(task);

		if (ts) {
			proc = sspt_proc_get_by_task_or_new(ts);
			sspt_proc_install(proc);
		}
	}

	return 0;
}

void print_vma(struct mm_struct *mm);

void print_vma(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	printk("### print_vma: START\n");\
	printk("### print_vma: START\n");

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		char *x = vma->vm_flags & VM_EXEC ? "x" : "-";
		char *r = vma->vm_flags & VM_READ ? "r" : "-";
		char *w = vma->vm_flags & VM_WRITE ? "w" : "-";
		char *name = vma->vm_file ? (char *)vma->vm_file->f_dentry->d_iname : "N/A";

		printk("### [%8lx..%8lx] %s%s%s pgoff=\'%8lu\' %s\n",
				vma->vm_start, vma->vm_end, x, r, w, vma->vm_pgoff, name);
	}
	printk("### print_vma:  END\n");
}

int register_usprobe(struct us_ip *ip)
{
	int ret = 0;

	ip->jprobe.priv_arg = ip;
	ip->jprobe.up.task = ip->page->file->proc->task;
	ip->jprobe.up.sm = ip->page->file->proc->sm;
	ret = dbi_register_ujprobe(&ip->jprobe);
	if (ret) {
		if (ret == -ENOEXEC) {
			pack_event_info(ERR_MSG_ID, RECORD_ENTRY, "dp",
					0x1,
					ip->jprobe.up.kp.addr);
		}
		DPRINTF ("dbi_register_ujprobe() failure %d", ret);
		return ret;
	}

	/* FIXME:
	 * Save opcode info into retprobe, for later
	 * check for instructions w\o obvious return
	 */
	memcpy(&ip->retprobe.up.kp.opcode, &ip->jprobe.up.kp.opcode, sizeof(kprobe_opcode_t));

	if (ip->flag_retprobe) {
		ip->retprobe.priv_arg = ip;
		ip->retprobe.up.task = ip->page->file->proc->task;
		ip->retprobe.up.sm = ip->page->file->proc->sm;
		ret = dbi_register_uretprobe(&ip->retprobe);
		if (ret) {
			EPRINTF ("dbi_register_uretprobe() failure %d", ret);
			return ret;
		}
	}

	return 0;
}

int unregister_usprobe(struct us_ip *ip)
{
	dbi_unregister_ujprobe(&ip->jprobe);

	if (ip->flag_retprobe) {
		dbi_unregister_uretprobe(&ip->retprobe);
	}

	return 0;
}
