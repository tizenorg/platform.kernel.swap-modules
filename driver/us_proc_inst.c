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
#include "../kprobe/dbi_uprobes.h"

#include "sspt/sspt.h"
#include "java_inst.h"

#define mm_read_lock(task, mm, atomic, lock) 			\
	mm = atomic ? task->active_mm : get_task_mm(task); 	\
	if (mm == NULL) {					\
		/* FIXME: */					\
		panic("ERRR mm_read_lock: mm == NULL\n");	\
	}							\
								\
	if (atomic) {						\
		lock = down_read_trylock(&mm->mmap_sem);	\
	} else {						\
		lock = 1;					\
		down_read(&mm->mmap_sem);			\
	}

#define mm_read_unlock(mm, atomic, lock) 			\
	if (lock) {						\
		up_read(&mm->mmap_sem);				\
	}							\
								\
	if (!atomic) {						\
		mmput(mm);					\
	}

#if defined(CONFIG_MIPS)
#	define ARCH_REG_VAL(regs, idx)	regs->regs[idx]
#elif defined(CONFIG_ARM)
#	define ARCH_REG_VAL(regs, idx)	regs->uregs[idx]
#else
#	define ARCH_REG_VAL(regs, idx)	0
#	warning ARCH_REG_VAL is not implemented for this architecture. FBI will work improperly or even crash!!!
#endif // ARCH

unsigned long ujprobe_event_pre_handler (struct us_ip *ip, struct pt_regs *regs);
void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);
int uretprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, struct us_ip *ip);


int us_proc_probes;

LIST_HEAD(proc_probes_list);


#ifdef ANDROID_APP
unsigned long android_app_vma_start = 0;
unsigned long android_app_vma_end = 0;
struct dentry *app_process_dentry = NULL;
#endif /* ANDROID_APP */

#ifdef SLP_APP
static struct dentry *launchpad_daemon_dentry = NULL;
EXPORT_SYMBOL_GPL(launchpad_daemon_dentry);
#endif /* SLP_APP */

#define print_event(fmt, args...) 						\
{ 										\
	char *buf[1024];							\
	sprintf(buf, fmt, ##args);						\
	pack_event_info(US_PROBE_ID, RECORD_ENTRY, "ds", 0x0badc0de, buf);	\
}

static inline int is_libonly(void)
{
	return !strcmp(us_proc_info.path,"*");
}

// is user-space instrumentation
static inline int is_us_instrumentation(void)
{
	return !!us_proc_info.path;
}

static struct sspt_procs *get_proc_probes_by_task(struct task_struct *task)
{
	struct sspt_procs *procs, *tmp;

	if (!is_libonly()) {
		if (task != current) {
			printk("ERROR get_proc_probes_by_task: \'task != current\'\n");
			return NULL;
		}

		return us_proc_info.pp;
	}

	list_for_each_entry_safe(procs, tmp, &proc_probes_list, list) {
		if (procs->tgid == task->tgid) {
			return procs;
		}
	}

	return NULL;
}

static void add_proc_probes(struct task_struct *task, struct sspt_procs *procs)
{
	list_add_tail(&procs->list, &proc_probes_list);
}

static struct sspt_procs *get_proc_probes_by_task_or_new(struct task_struct *task)
{
	struct sspt_procs *procs = get_proc_probes_by_task(task);
	if (procs == NULL) {
		procs = sspt_procs_copy(us_proc_info.pp, task);
		add_proc_probes(task, procs);
	}

	return procs;
}

#ifdef SLP_APP
static int is_slp_app_with_dentry(struct vm_area_struct *vma,
								  struct dentry *dentry)
{
	struct vm_area_struct *slp_app_vma = NULL;

	if (vma->vm_file->f_dentry == launchpad_daemon_dentry) {
		slp_app_vma = vma;
		while (slp_app_vma) {
			if (slp_app_vma->vm_file) {
				if (slp_app_vma->vm_file->f_dentry == dentry &&
					slp_app_vma->vm_pgoff == 0) {
					return 1;
				}
			}
			slp_app_vma = slp_app_vma->vm_next;
		}
	}

	return 0;
}
#endif /* SLP_APP */

#ifdef ANDROID_APP
static int is_android_app_with_dentry(struct vm_area_struct *vma,
									  struct dentry *dentry)
{
	struct vm_area_struct *android_app_vma = NULL;

	if (vma->vm_file->f_dentry == app_process_dentry) {
		android_app_vma = vma;
		while (android_app_vma) {
			if (android_app_vma->vm_file) {
				if (android_app_vma->vm_file->f_dentry == dentry) {
					android_app_vma_start = android_app_vma->vm_start;
					android_app_vma_end = android_app_vma->vm_end;
					return 1;
				}
			}
			android_app_vma = android_app_vma->vm_next;
		}
	}

	return 0;
}
#endif /* ANDROID_APP */

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

static int check_vma(struct vm_area_struct *vma)
{
#ifndef __ANDROID
	return vma->vm_file && !(vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_ACCOUNT) ||
			!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) ||
			!(vma->vm_flags & (VM_READ | VM_MAYREAD)));
#else // __ANDROID
	return vma->vm_file && !(vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC));
#endif // __ANDROID
}

static int find_task_by_path (const char *path, struct task_struct **p_task, struct list_head *tids)
{
	int found = 0;
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct dentry *dentry = dentry_by_path(path);

	*p_task = NULL;

	/* find corresponding dir entry, this is also check for valid path */
	// TODO: test - try to instrument process with non-existing path
	// TODO: test - try to instrument process  with existing path and delete file just after start
	if (dentry == NULL) {
		return -EINVAL;
	}

	rcu_read_lock();
	for_each_process (task)	{

		if  ( 0 != inst_pid && ( inst_pid != task->pid ) )
			continue;

		mm = get_task_mm(task);
		if (!mm)
			continue;
		vma = mm->mmap;
		while (vma) {
			if (check_vma(vma)) {
				if (vma->vm_file->f_dentry == dentry) {
					if (!*p_task) {
						*p_task = task;
						get_task_struct (task);
					}
						//break;
				}
#ifdef SLP_APP
				if (!*p_task) {
					if (is_slp_app_with_dentry(vma, dentry)) {
						*p_task = task;
						get_task_struct(task);
					}
				}
#endif /* SLP_APP */
#ifdef ANDROID_APP
				if (!*p_task) {
					if (is_android_app_with_dentry(vma, dentry)) {
						*p_task = task;
						get_task_struct(task);
					}
				}
#endif /* ANDROID_APP */
			}
			vma = vma->vm_next;
		}
		// only decrement usage count on mm since we cannot sleep here
		atomic_dec(&mm->mm_users);
		if (found)
			break;
	}
	rcu_read_unlock();

	if (*p_task) {
		DPRINTF ("found pid %d for %s.", (*p_task)->pid, path);
		*p_task = (*p_task)->group_leader;
		gl_nNotifyTgid = (*p_task)->tgid;
	} else {
		DPRINTF ("pid for %s not found!", path);
	}

	return 0;
}

static void set_mapping_file(struct sspt_file *file,
		const struct sspt_procs *procs,
		const struct task_struct *task,
		const struct vm_area_struct *vma);

int install_otg_ip(unsigned long addr,
			kprobe_pre_entry_handler_t pre_handler,
			unsigned long jp_handler,
			kretprobe_handler_t rp_handler)
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
			struct sspt_procs *procs = get_proc_probes_by_task(task);
			struct ip_data pd = {
					.offset = offset_addr,
					.pre_handler = pre_handler,
					.jp_handler = jp_handler,
					.rp_handler = rp_handler,
					.flag_retprobe = 1
			};

			struct sspt_file *file = sspt_procs_find_file_or_new(procs, dentry, name);
			struct sspt_page *page = sspt_get_page(file, offset_addr);
			struct us_ip *ip = sspt_find_ip(page, offset_addr & ~PAGE_MASK);

			if (!file->loaded) {
				set_mapping_file(file, procs, task, vma);
				file->loaded = 1;
			}

			if (ip == NULL) {
				// TODO: sspt_procs_find_file_or_new --> sspt_procs_find_file ?!
				struct sspt_file *file = sspt_procs_find_file_or_new(procs, dentry, name);
				sspt_file_add_ip(file, &pd);

				/* if addr mapping, that probe install, else it be installed in do_page_fault handler */
				if (page_present(mm, addr)) {
					ip = sspt_find_ip(page, offset_addr & ~PAGE_MASK);
					sspt_set_ip_addr(ip, page, file);

					// TODO: error
					ret = register_usprobe_my(task, ip);
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

static int uninstall_kernel_probe (unsigned long addr, int uflag, int kflag, kernel_probe_t ** pprobe)
{
	kernel_probe_t *probe = NULL;
	int iRet = 0;
	if (probes_flags & kflag) {
		probe = find_probe(addr);
		if (probe) {
			iRet = remove_probe_from_list (addr);
			if (iRet)
				EPRINTF ("remove_probe_from_list(0x%lx) result=%d!", addr, iRet);
			if (pprobe)
				*pprobe = NULL;
		}
		probes_flags &= ~kflag;
	}
	if (us_proc_probes & uflag) {
		if (!(probes_flags & uflag)) {
			if (probe) {
				iRet = unregister_kernel_probe(probe);
				if (iRet) {
					EPRINTF ("unregister_kernel_probe(0x%lx) result=%d!",
							addr, iRet);
					return iRet;
				}
			}
		}
		us_proc_probes &= ~uflag;
	}
	return iRet;
}

static int uninstall_us_proc_probes(struct task_struct *task, struct sspt_procs *procs, enum US_FLAGS flag);

int deinst_usr_space_proc (void)
{
	int iRet = 0, found = 0;
	struct task_struct *task = NULL;

	if (!is_us_instrumentation()) {
		return 0;
	}

	iRet = uninstall_kernel_probe (pf_addr, US_PROC_PF_INSTLD,
			0, &pf_probe);
	if (iRet)
		EPRINTF ("uninstall_kernel_probe(do_page_fault) result=%d!", iRet);

	iRet = uninstall_kernel_probe (cp_addr, US_PROC_CP_INSTLD,
			0, &cp_probe);
	if (iRet)
		EPRINTF ("uninstall_kernel_probe(copy_process) result=%d!", iRet);

        iRet = uninstall_kernel_probe (mr_addr, US_PROC_MR_INSTLD,
                        0, &mr_probe);
        if (iRet)
                EPRINTF ("uninstall_kernel_probe(mm_release) result=%d!", iRet);

	iRet = uninstall_kernel_probe (exit_addr, US_PROC_EXIT_INSTLD,
			0, &exit_probe);
	if (iRet)
		EPRINTF ("uninstall_kernel_probe(do_exit) result=%d!", iRet);

	iRet = uninstall_kernel_probe (unmap_addr, US_PROC_UNMAP_INSTLD,
			0, &unmap_probe);
	if (iRet)
		EPRINTF ("uninstall_kernel_probe(do_munmap) result=%d!", iRet);

	if (is_libonly()) {
		struct sspt_procs *procs;

		for_each_process(task)	{
			procs = get_proc_probes_by_task(task);
			if (procs) {
				int ret = uninstall_us_proc_probes(task, procs, US_UNREGS_PROBE);
				if (ret) {
					EPRINTF ("failed to uninstall IPs (%d)!", ret);
				}

				dbi_unregister_all_uprobes(task, 1);
			}
		}
	}
	else
	{
		if (us_proc_info.tgid == 0)
			return 0;
			rcu_read_lock ();
		for_each_process (task)
		{
			if (task->tgid == us_proc_info.tgid)
			{
				found = 1;
				get_task_struct (task);
				break;
			}
		}
		rcu_read_unlock ();
		if (found)
		{
			int i, ret;
			// uninstall IPs
			ret = uninstall_us_proc_probes(task, us_proc_info.pp, US_UNREGS_PROBE);
			if (ret != 0) {
				EPRINTF ("failed to uninstall IPs %d!", ret);
			}

			put_task_struct (task);

			printk("### 1 ### dbi_unregister_all_uprobes:\n");
			dbi_unregister_all_uprobes(task, 1);
			us_proc_info.tgid = 0;
			for(i = 0; i < us_proc_info.libs_count; i++)
				us_proc_info.p_libs[i].loaded = 0;
		}
	}

	return iRet;
}
static int install_kernel_probe (unsigned long addr, int uflag, int kflag, kernel_probe_t ** pprobe)
{
	kernel_probe_t *probe = NULL;
	int iRet = 0;

	DPRINTF("us_proc_probes = 0x%x, uflag = 0x%x, "
			"probes_flags = 0x%x, kflag = 0x%x",
			us_proc_probes, uflag, probes_flags, kflag);

	if (!(probes_flags & kflag)) {
		iRet = add_probe_to_list (addr, &probe);
		if (iRet) {
			EPRINTF ("add_probe_to_list(0x%lx) result=%d!", addr, iRet);
			return iRet;
		}
		probes_flags |= kflag;
	}
	if (!(us_proc_probes & uflag)) {
		if (!(probes_flags & uflag)) {
			iRet = register_kernel_probe (probe);
			if (iRet) {
				EPRINTF ("register_kernel_probe(0x%lx) result=%d!", addr, iRet);
				return iRet;
			}
		}
		us_proc_probes |= uflag;
	}

	if (probe)
		*pprobe = probe;

	return 0;
}

static void install_proc_probes(struct task_struct *task, struct sspt_procs *procs, int atomic);

int inst_usr_space_proc (void)
{
	int ret, i;
	struct task_struct *task = NULL;

	if (!is_us_instrumentation()) {
		return 0;
	}

	DPRINTF("User space instr");

#ifdef SLP_APP
	launchpad_daemon_dentry = dentry_by_path("/usr/bin/launchpad_preloading_preinitializing_daemon");
	if (launchpad_daemon_dentry == NULL) {
		return -EINVAL;
	}

#endif /* SLP_APP */

#ifdef ANDROID_APP
	app_process_dentry = dentry_by_path("/system/bin/app_process");
	if (app_process_dentry == NULL) {
		return -EINVAL;
	}

	android_app_vma_start = 0;
	android_app_vma_end = 0;
#endif /* ANDROID_APP */

	for (i = 0; i < us_proc_info.libs_count; i++) {
		us_proc_info.p_libs[i].loaded = 0;
	}
	/* check whether process is already running
	 * 1) if process is running - look for the libraries in the process maps
	 * 1.1) check if page for symbol does exist
	 * 1.1.1) if page exists - instrument it
	 * 1.1.2) if page does not exist - make sure that do_page_fault handler is installed
	 * 2) if process is not running - make sure that do_page_fault handler is installed
	 * */

	if (is_libonly())
	{
		// FIXME: clear_task_inst_info();
		for_each_process (task) {
			struct sspt_procs *procs;

			if (task->flags & PF_KTHREAD){
				DPRINTF("ignored kernel thread %d\n",
					task->pid);
				continue;
			}

			procs = get_proc_probes_by_task_or_new(task);
			DPRINTF("trying process");
			install_proc_probes(task, procs, 1);
			//put_task_struct (task);
		}
	}
	else
	{
		ret = find_task_by_path (us_proc_info.path, &task, NULL);
		if ( task  )
		{
			DPRINTF("task found. installing probes");
			us_proc_info.tgid = task->pid;
			install_proc_probes(task, us_proc_info.pp, 0);
			put_task_struct (task);
		}
	}

	// enable 'do_page_fault' probe to detect when they will be loaded
	ret = install_kernel_probe (pf_addr, US_PROC_PF_INSTLD, 0, &pf_probe);
	if (ret != 0)
	{
		EPRINTF ("install_kernel_probe(do_page_fault) result=%d!", ret);
		return ret;
	}
	// enable 'do_exit' probe to detect for remove task_struct
	ret = install_kernel_probe (exit_addr, US_PROC_EXIT_INSTLD, 0, &exit_probe);
	if (ret != 0)
	{
		EPRINTF ("install_kernel_probe(do_exit) result=%d!", ret);
		return ret;
	}
	/* enable 'copy_process' */
	ret = install_kernel_probe (cp_addr, US_PROC_CP_INSTLD, 0, &cp_probe);
	if (ret != 0)
	{
		EPRINTF ("instpall_kernel_probe(copy_process) result=%d!", ret);
		return ret;
	}

	// enable 'mm_release' probe to detect when for remove user space probes
	ret = install_kernel_probe (mr_addr, US_PROC_MR_INSTLD, 0, &mr_probe);
	if (ret != 0)
	{
		EPRINTF ("install_kernel_probe(mm_release) result=%d!", ret);
		return ret;
	}

	// enable 'do_munmap' probe to detect when for remove user space probes
	ret = install_kernel_probe (unmap_addr, US_PROC_UNMAP_INSTLD, 0, &unmap_probe);
	if (ret != 0)
	{
		EPRINTF ("install_kernel_probe(do_munmap) result=%d!", ret);
		return ret;
	}
	return 0;
}

#include "../../tools/gpmu/probes/entry_data.h"

void do_page_fault_j_pre_code(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *task = current->group_leader;

	if (task->flags & PF_KTHREAD) {
		DPRINTF("ignored kernel thread %d\n", task->pid);
		return;
	}

	if (is_us_instrumentation()) {
		// for x86 do_page_fault is do_page_fault(struct pt_regs *regs, unsigned long error_code)
		// instead of do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs) for arm
#ifdef CONFIG_X86
		unsigned long address = read_cr2();
		swap_put_entry_data((void *)address, &sa_dpf);
#else /* CONFIG_X86 */
		swap_put_entry_data((void *)addr, &sa_dpf);
#endif /* CONFIG_X86 */
	}
}
EXPORT_SYMBOL_GPL(do_page_fault_j_pre_code);


unsigned long imi_sum_time = 0;
unsigned long imi_sum_hit = 0;

static void set_mapping_file(struct sspt_file *file,
		const struct sspt_procs *procs,
		const struct task_struct *task,
		const struct vm_area_struct *vma)
{
	int app_flag = (vma->vm_file->f_dentry == procs->dentry);

	file->vm_start = vma->vm_start;
	file->vm_end = vma->vm_end;

	pack_event_info(DYN_LIB_PROBE_ID, RECORD_ENTRY, "dspdd",
			task->tgid, file->name, vma->vm_start,
			vma->vm_end - vma->vm_start, app_flag);
}

void print_vma(struct mm_struct *mm);

static int register_us_page_probe(struct sspt_page *page,
		const struct sspt_file *file,
		struct task_struct *task)
{
	int err = 0;
	struct us_ip *ip, *n;

	spin_lock(&page->lock);

	if (sspt_page_is_install(page)) {
		printk("page %lx in %s task[tgid=%u, pid=%u] already installed\n",
				page->offset, file->dentry->d_iname, task->tgid, task->pid);
		print_vma(task->mm);
		goto unlock;
	}

	sspt_page_assert_install(page);
	sspt_set_all_ip_addr(page, file);

	list_for_each_entry_safe(ip, n, &page->ip_list, list) {
		err = register_usprobe_my(task, ip);
		if (err == -ENOEXEC) {
			list_del(&ip->list);
			free_ip(ip);
			continue;
		} else if (err) {
			EPRINTF("Failed to install probe");
		}
	}
unlock:
	sspt_page_installed(page);
	spin_unlock(&page->lock);

	return 0;
}

static int unregister_us_page_probe(struct task_struct *task,
		struct sspt_page *page, enum US_FLAGS flag)
{
	int err = 0;
	struct us_ip *ip;

	spin_lock(&page->lock);
	if (!sspt_page_is_install(page)) {
		spin_unlock(&page->lock);
		return 0;
	}

	list_for_each_entry(ip, &page->ip_list, list) {
		err = unregister_usprobe_my(task, ip, flag);
		if (err != 0) {
			//TODO: ERROR
			break;
		}
	}

	if (flag != US_DISARM) {
		sspt_page_uninstalled(page);
	}
	spin_unlock(&page->lock);

	return err;
}

static void install_page_probes(unsigned long page_addr, struct task_struct *task, struct sspt_procs *procs, int atomic)
{
	int lock;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	mm_read_lock(task, mm, atomic, lock);

	vma = find_vma(mm, page_addr);
	if (vma && check_vma(vma)) {
		struct dentry *dentry = vma->vm_file->f_dentry;
		struct sspt_file *file = sspt_procs_find_file(procs, dentry);
		if (file) {
			struct sspt_page *page;
			if (!file->loaded) {
				set_mapping_file(file, procs, task, vma);
				file->loaded = 1;
			}

			page = sspt_find_page_mapped(file, page_addr);
			if (page) {
				register_us_page_probe(page, file, task);
			}
		}
	}

	mm_read_unlock(mm, atomic, lock);
}

static void install_file_probes(struct task_struct *task, struct mm_struct *mm, struct sspt_file *file)
{
	struct sspt_page *page = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;
	int i, table_size = (1 << file->page_probes_hash_bits);

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		swap_hlist_for_each_entry_rcu(page, node, head, hlist) {
			register_us_page_probe(page, file, task);
		}
	}
}

static void install_proc_probes(struct task_struct *task, struct sspt_procs *procs, int atomic)
{
	int lock;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	mm_read_lock(task, mm, atomic, lock);

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			struct dentry *dentry = vma->vm_file->f_dentry;
			struct sspt_file *file = sspt_procs_find_file(procs, dentry);
			if (file) {
				if (!file->loaded) {
					set_mapping_file(file, procs, task, vma);
					file->loaded = 1;
				}

				install_file_probes(task, mm, file);
			}
		}
	}

	mm_read_unlock(mm, atomic, lock);
}

static int check_install_pages_in_file(struct task_struct *task, struct sspt_file *file)
{
	int i;
	int table_size = (1 << file->page_probes_hash_bits);
	struct sspt_page *page;
	struct hlist_node *node, *tmp;
	struct hlist_head *head;

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		swap_hlist_for_each_entry_safe (page, node, tmp, head, hlist) {
			if (page->install) {
				return 1;
			}
		}
	}

	return 0;
}

static int unregister_us_file_probes(struct task_struct *task, struct sspt_file *file, enum US_FLAGS flag)
{
	int i, err = 0;
	int table_size = (1 << file->page_probes_hash_bits);
	struct sspt_page *page;
	struct hlist_node *node, *tmp;
	struct hlist_head *head;

	for (i = 0; i < table_size; ++i) {
		head = &file->page_probes_table[i];
		swap_hlist_for_each_entry_safe (page, node, tmp, head, hlist) {
			err = unregister_us_page_probe(task, page, flag);
			if (err != 0) {
				// TODO: ERROR
				return err;
			}
		}
	}

	if (flag != US_DISARM) {
		file->loaded = 0;
	}

	return err;
}

static int uninstall_us_proc_probes(struct task_struct *task, struct sspt_procs *procs, enum US_FLAGS flag)
{
	int err = 0;
	struct sspt_file *file;

	list_for_each_entry_rcu(file, &procs->file_list, list) {
		err = unregister_us_file_probes(task, file, flag);
		if (err != 0) {
			// TODO:
			return err;
		}
	}

	return err;
}

static pid_t find_proc_by_task(const struct task_struct *task, struct dentry *dentry)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = task->active_mm;
	if (mm == NULL) {
		return 0;
	}

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			if (vma->vm_file->f_dentry == dentry) {
				return task->tgid;
			}
#ifdef SLP_APP
			if (is_slp_app_with_dentry(vma, dentry)) {
				return task->tgid;
			}
#endif /* SLP_APP */
#ifdef ANDROID_APP
			if (is_android_app_with_dentry(vma, dentry)) {
				return task->tgid;
			}
#endif /* ANDROID_APP */
		}
	}

	return 0;
}

void do_page_fault_ret_pre_code (void)
{
	struct task_struct *task = current->group_leader;
	struct mm_struct *mm = task->mm;
	struct sspt_procs *procs = NULL;
	/*
	 * Because process threads have same address space
	 * we instrument only group_leader of all this threads
	 */
	unsigned long addr = 0;
	int valid_addr;

	// overhead
	struct timeval imi_tv1;
	struct timeval imi_tv2;
#define USEC_IN_SEC_NUM				1000000

	if (task->flags & PF_KTHREAD) {
		DPRINTF("ignored kernel thread %d\n", task->pid);
		return;
	}

	if (!is_us_instrumentation()) {
		return;
	}

	addr = (unsigned long)swap_get_entry_data(&sa_dpf);

	if (addr == 0) {
		printk("WARNING: do_page_fault_ret_pre_code addr = 0\n");
		return;
	}




	valid_addr = mm && page_present(mm, addr);
	if (!valid_addr) {
		return;
	}

	if (is_libonly()) {
		procs = get_proc_probes_by_task_or_new(task);
	} else {
		// find task
		if (us_proc_info.tgid == 0) {
			pid_t tgid = find_proc_by_task(task, us_proc_info.m_f_dentry);
			if (tgid) {
				us_proc_info.tgid = gl_nNotifyTgid = tgid;

				/* install probes in already mapped memory */
				install_proc_probes(task, us_proc_info.pp, 1);
			}
		}

		if (us_proc_info.tgid == task->tgid) {
			procs = us_proc_info.pp;
		}
	}

	if (procs) {
		unsigned long page = addr & PAGE_MASK;

		// overhead
		do_gettimeofday(&imi_tv1);
		install_page_probes(page, task, procs, 1);
		do_gettimeofday(&imi_tv2);
		imi_sum_hit++;
		imi_sum_time += ((imi_tv2.tv_sec - imi_tv1.tv_sec) *  USEC_IN_SEC_NUM +
				(imi_tv2.tv_usec - imi_tv1.tv_usec));
	}
}

EXPORT_SYMBOL_GPL(do_page_fault_ret_pre_code);


void do_exit_probe_pre_code (void)
{
	// TODO: remove task
}
EXPORT_SYMBOL_GPL(do_exit_probe_pre_code);

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

static int remove_unmap_probes(struct task_struct *task, struct sspt_procs *procs, unsigned long start, size_t len)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;

	if ((start & ~PAGE_MASK) || start > TASK_SIZE || len > TASK_SIZE - start) {
		return -EINVAL;
	}

	if ((len = PAGE_ALIGN(len)) == 0) {
		return -EINVAL;
	}

	vma = find_vma(mm, start);
	if (vma && check_vma(vma)) {
		struct sspt_file *file;
		unsigned long end = start + len;
		struct dentry *dentry = vma->vm_file->f_dentry;

		file = sspt_procs_find_file(procs, dentry);
		if (file) {
			if (vma->vm_start == start || vma->vm_end == end) {
				unregister_us_file_probes(task, file, US_NOT_RP2);
				file->loaded = 0;
			} else {
				unsigned long page_addr;
				struct sspt_page *page;

				for (page_addr = vma->vm_start; page_addr < vma->vm_end; page_addr += PAGE_SIZE) {
					page = sspt_find_page_mapped(file, page_addr);
					if (page) {
						unregister_us_page_probe(task, page, US_NOT_RP2);
					}
				}

				if (check_install_pages_in_file(task, file)) {
					file->loaded = 0;
				}
			}
		}
	}

	return 0;
}

void do_munmap_probe_pre_code(struct mm_struct *mm, unsigned long start, size_t len)
{
	struct sspt_procs *procs = NULL;
	struct task_struct *task = current;

	//if user-space instrumentation is not set
	if (!is_us_instrumentation()) {
		return;
	}

	if (is_libonly()) {
		procs = get_proc_probes_by_task(task);
	} else {
		if (task->tgid == us_proc_info.tgid) {
			procs = us_proc_info.pp;
		}
	}

	if (procs) {
		if (remove_unmap_probes(task, procs, start, len)) {
			printk("ERROR do_munmap: start=%lx, len=%x\n", start, len);
		}
	}
}
EXPORT_SYMBOL_GPL(do_munmap_probe_pre_code);

void mm_release_probe_pre_code(void)
{
	struct task_struct *task = current;
	struct sspt_procs *procs = NULL;

	if (!is_us_instrumentation() || task->tgid != task->pid) {
		return;
	}

	if (is_libonly()) {
		procs = get_proc_probes_by_task(task);
	} else {
		if (task->tgid == us_proc_info.tgid) {
			procs = get_proc_probes_by_task(task);
			us_proc_info.tgid = 0;
		}
	}

	if (procs) {
		int ret = uninstall_us_proc_probes(task, procs, US_NOT_RP2);
		if (ret != 0) {
			EPRINTF ("failed to uninstall IPs (%d)!", ret);
		}

		dbi_unregister_all_uprobes(task, 1);
	}
}
EXPORT_SYMBOL_GPL(mm_release_probe_pre_code);


static void recover_child(struct task_struct *child_task, struct sspt_procs *procs)
{
	uninstall_us_proc_probes(child_task, procs, US_DISARM);
	dbi_disarm_urp_inst_for_task(current, child_task);
}

static void rm_uprobes_child(struct task_struct *new_task)
{
	if (is_libonly()) {
		struct sspt_procs *procs = get_proc_probes_by_task(current);
		if(procs) {
			recover_child(new_task, procs);
		}
	} else {
		if(us_proc_info.tgid == current->tgid) {
			recover_child(new_task, us_proc_info.pp);
		}
	}
}

void copy_process_ret_pre_code(struct task_struct *p)
{
	if(!p || IS_ERR(p))
		return;

	if(p->mm != current->mm)    // check flags CLONE_VM
		rm_uprobes_child(p);
}

static DEFINE_PER_CPU(struct us_ip *, gpCurIp) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpCurIp);
static DEFINE_PER_CPU(struct pt_regs *, gpUserRegs) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpUserRegs);

unsigned long ujprobe_event_pre_handler(struct us_ip *ip, struct pt_regs *regs)
{
	__get_cpu_var (gpCurIp) = ip;
	__get_cpu_var (gpUserRegs) = regs;
	return 0;
}

void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	struct us_ip *ip = __get_cpu_var(gpCurIp);
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;

#ifdef __ANDROID
	struct pt_regs *regs = __get_cpu_var(gpUserRegs);
	if (is_java_inst_enabled() && handle_java_event(regs)) {
		return;
	}
#endif /* __ANDROID */


#if defined(CONFIG_ARM)
	if (ip->offset & 0x01)
	{
		pack_event_info (US_PROBE_ID, RECORD_ENTRY, "ppppppp", addr | 0x01, arg1, arg2, arg3, arg4, arg5, arg6);
	}else{
		pack_event_info (US_PROBE_ID, RECORD_ENTRY, "ppppppp", addr, arg1, arg2, arg3, arg4, arg5, arg6);
	}
#else
	pack_event_info (US_PROBE_ID, RECORD_ENTRY, "ppppppp", addr, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
	// Mr_Nobody: uncomment for valencia
	//unregister_usprobe(current, ip, 1);
	dbi_uprobe_return ();
}

static void send_plt(struct us_ip *ip)
{
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;
	struct vm_area_struct *vma = find_vma(current->mm, addr);

	if (vma && check_vma(vma)) {
		char *name = NULL;
		unsigned long real_addr;
		unsigned long real_got = current->mm->exe_file == vma->vm_file ?
				ip->got_addr :
				ip->got_addr + vma->vm_start;

		if (!read_proc_vm_atomic(current, real_got, &real_addr, sizeof(real_addr))) {
			printk("Failed to read got %lx at memory address %lx!\n", ip->got_addr, real_got);
			return;
		}

		vma = find_vma(current->mm, real_addr);
		if (vma && (vma->vm_start <= real_addr) && (vma->vm_end > real_addr)) {
			name = vma->vm_file ? vma->vm_file->f_dentry->d_iname : NULL;
		} else {
			printk("Failed to get vma, includes %lx address\n", real_addr);
			return;
		}

		if (name) {
			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppsp", addr, real_addr, name, real_addr - vma->vm_start);
		} else {
			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppp", addr, real_addr, real_addr - vma->vm_start);
		}
	}
}

int uretprobe_event_handler(struct kretprobe_instance *probe, struct pt_regs *regs, struct us_ip *ip)
{
	int retval = regs_return_value(regs);
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;

	if (ip->got_addr && ip->flag_got == 0) {
		send_plt(ip);
		ip->flag_got = 1;
	}

#if defined(CONFIG_ARM)
	if (ip->offset & 0x01)
	{
		pack_event_info (US_PROBE_ID, RECORD_RET, "pd", addr | 0x01, retval);
	}else{
		pack_event_info (US_PROBE_ID, RECORD_RET, "pd", addr, retval);
	}
#else
	pack_event_info (US_PROBE_ID, RECORD_RET, "pd", addr, retval);
#endif
	// Mr_Nobody: uncomment for valencia
	//unregister_usprobe(current, ip, 1);
	return 0;
}

int register_usprobe(struct task_struct *task, struct us_ip *ip, int atomic)
{
	int ret = 0;
	ip->jprobe.kp.tgid = task->tgid;

	if (ip->jprobe.entry == NULL) {
		ip->jprobe.entry = (kprobe_opcode_t *)ujprobe_event_handler;
		DPRINTF("Set default event handler for %x\n", ip->offset);
	}

	if (ip->jprobe.pre_entry == NULL) {
		ip->jprobe.pre_entry = (kprobe_pre_entry_handler_t)ujprobe_event_pre_handler;
		DPRINTF("Set default pre handler for %x\n", ip->offset);
	}

	ip->jprobe.priv_arg = ip;
	ret = dbi_register_ujprobe(task, &ip->jprobe, atomic);
	if (ret) {
		if (ret == -ENOEXEC) {
			pack_event_info(ERR_MSG_ID, RECORD_ENTRY, "dp",
					0x1,
					ip->jprobe.kp.addr);
		}
		DPRINTF ("dbi_register_ujprobe() failure %d", ret);
		return ret;
	}

	/*
	 * Save opcode info into retprobe, for later
	 * check for instructions w\o obvious return
	 */
	memcpy(&ip->retprobe.kp.opcode, &ip->jprobe.kp.opcode, sizeof(kprobe_opcode_t));

	if (ip->flag_retprobe) {
		// Mr_Nobody: comment for valencia
		ip->retprobe.kp.tgid = task->tgid;
		if (ip->retprobe.handler == NULL) {
			ip->retprobe.handler = (kretprobe_handler_t)uretprobe_event_handler;
			DPRINTF("Set default ret event handler for %x\n", ip->offset);
		}

		ip->retprobe.priv_arg = ip;
		ret = dbi_register_uretprobe(task, &ip->retprobe, atomic);
		if (ret) {
			EPRINTF ("dbi_register_uretprobe() failure %d", ret);
			return ret;
		}
	}

	return 0;
}

int unregister_usprobe(struct task_struct *task, struct us_ip *ip, int atomic, int not_rp2)
{
	dbi_unregister_ujprobe(task, &ip->jprobe, atomic);

	if (ip->flag_retprobe) {
		dbi_unregister_uretprobe(task, &ip->retprobe, atomic, not_rp2);
	}

	return 0;
}

unsigned long get_stack_size(struct task_struct *task,
		struct pt_regs *regs)
{
#ifdef CONFIG_ADD_THREAD_STACK_INFO
	return (task->stack_start - dbi_get_stack_ptr(regs));
#else
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = NULL;
	unsigned long result = 0;
    int atomic = in_atomic();

	mm = (atomic ? task->active_mm: get_task_mm(task));

	if (mm) {
		if (!atomic)
			down_read(&mm->mmap_sem);

		vma = find_vma(mm, dbi_get_stack_ptr(regs));

		if (vma)
			result = vma->vm_end - dbi_get_stack_ptr(regs);
		else
			result = 0;

		if (!atomic) {
			up_read(&mm->mmap_sem);
			mmput(mm);
		}
	}

	return result;
#endif
}
EXPORT_SYMBOL_GPL(get_stack_size);

unsigned long get_stack(struct task_struct *task, struct pt_regs *regs,
		char *buf, unsigned long sz)
{
	unsigned long stack_sz = get_stack_size(task, regs);
	unsigned long real_sz = (stack_sz > sz ? sz: stack_sz);
	int res = read_proc_vm_atomic(task, dbi_get_stack_ptr(regs), buf, real_sz);
	return res;
}
EXPORT_SYMBOL_GPL(get_stack);

int dump_to_trace(probe_id_t probe_id, void *addr, const char *buf,
		unsigned long sz)
{
	unsigned long rest_sz = sz;
	const char *data = buf;

	while (rest_sz >= EVENT_MAX_SIZE) {
		pack_event_info(probe_id, RECORD_ENTRY, "pa",
				addr, EVENT_MAX_SIZE, data);
		rest_sz -= EVENT_MAX_SIZE;
		data += EVENT_MAX_SIZE;
	}

	if (rest_sz > 0)
		pack_event_info(probe_id, RECORD_ENTRY, "pa", addr, rest_sz, data);

	return 0;
}
EXPORT_SYMBOL_GPL(dump_to_trace);

int dump_backtrace(probe_id_t probe_id, struct task_struct *task,
		void *addr, struct pt_regs *regs, unsigned long sz)
{
	unsigned long real_sz = 0;
	char *buf = NULL;

	buf = (char *)kmalloc(sz, GFP_ATOMIC);

	if (buf != NULL) {
		real_sz = get_stack(task, regs, buf, sz);
		if (real_sz > 0)
			dump_to_trace(probe_id, addr, buf, real_sz);
		kfree(buf);
		return 0;
	} else {
		return -1;
	}
}
EXPORT_SYMBOL_GPL(dump_backtrace);

struct kretprobe_instance *find_ri(struct task_struct *task, struct us_ip *ip)
{
	struct hlist_node *item, *tmp_node;
	struct kretprobe_instance *ri;

	if (ip == NULL)
		return NULL;

	hlist_for_each_safe (item, tmp_node, &ip->retprobe.used_instances) {
		ri = hlist_entry (item, struct kretprobe_instance, uflist);

		if (ri->task && ri->task->pid == task->pid &&
				ri->task->tgid == task->tgid)
			return ri;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(find_ri);

unsigned long get_ret_addr(struct task_struct *task, struct us_ip *ip)
{
	struct kretprobe_instance *ri = find_ri(task, ip);;
	if (ri)
		return (unsigned long)ri->ret_addr;
	else
		return dbi_get_ret_addr(task_pt_regs(task));
}
EXPORT_SYMBOL_GPL(get_ret_addr);

unsigned long get_entry_sp(struct task_struct *task, struct us_ip *ip)
{
	struct kretprobe_instance *ri = find_ri(task, ip);
	if (ri)
		return (unsigned long)ri->sp;
	else
		return dbi_get_stack_ptr(task_pt_regs(task));
}
EXPORT_SYMBOL_GPL(get_entry_sp);
