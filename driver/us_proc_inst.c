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
#include "helper.h"
#include "us_slot_manager.h"

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

unsigned long ujprobe_event_pre_handler (struct us_ip *ip, struct pt_regs *regs);
void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);
int uretprobe_event_handler(struct uretprobe_instance *probe, struct pt_regs *regs, struct us_ip *ip);


#define print_event(fmt, args...) 						\
{ 										\
	char *buf[1024];							\
	sprintf(buf, fmt, ##args);						\
	pack_event_info(US_PROBE_ID, RECORD_ENTRY, "ds", 0x0badc0de, buf);	\
}

int is_libonly(void)
{
	return !strcmp(us_proc_info.path,"*");
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
			struct sspt_procs *procs = sspt_procs_get_by_task(task);
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
					ret = sspt_register_usprobe(task, ip);
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
	struct sspt_procs *procs;

	if (!is_us_instrumentation()) {
		return 0;
	}

	unregister_helper();

	if (iRet)
		EPRINTF ("uninstall_kernel_probe(do_munmap) result=%d!", iRet);


	for_each_process(task) {
		procs = sspt_procs_get_by_task(task);
		if (procs) {
			int ret = uninstall_us_proc_probes(task, procs, US_UNREGS_PROBE);
			if (ret) {
				EPRINTF ("failed to uninstall IPs (%d)!", ret);
			}

			dbi_unregister_all_uprobes(task);
		}
	}

	return iRet;
}

int inst_usr_space_proc (void)
{
	int ret, i;
	struct task_struct *task = NULL;

	if (!is_us_instrumentation()) {
		return 0;
	}

	DPRINTF("User space instr");

	ret = register_helper();
	if (ret) {
		return ret;
	}

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

			procs = sspt_procs_get_by_task_or_new(task);
			DPRINTF("trying process");
			install_proc_probes(task, procs);
			//put_task_struct (task);
		}
	}
	else
	{
		ret = find_task_by_path(us_proc_info.path, &task, NULL);
		if (task) {
			struct sspt_procs *procs;

			procs = sspt_procs_get_by_task_or_new(task);

			us_proc_info.tgid = task->pid;
			install_proc_probes(task, procs);
			put_task_struct(task);
		}
	}

	return 0;
}

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
		err = sspt_register_usprobe(task, ip);
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

int unregister_us_page_probe(struct task_struct *task,
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
		err = sspt_unregister_usprobe(task, ip, flag);
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

void install_page_probes(unsigned long page_addr, struct task_struct *task, struct sspt_procs *procs)
{
	int lock, atomic;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	atomic = in_atomic();
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

void install_proc_probes(struct task_struct *task, struct sspt_procs *procs)
{
	int lock, atomic;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	atomic = in_atomic();
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

int check_install_pages_in_file(struct task_struct *task, struct sspt_file *file)
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

int unregister_us_file_probes(struct task_struct *task, struct sspt_file *file, enum US_FLAGS flag)
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

int uninstall_us_proc_probes(struct task_struct *task, struct sspt_procs *procs, enum US_FLAGS flag)
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

pid_t find_proc_by_task(const struct task_struct *task, struct dentry *dentry)
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
		}
	}

	return 0;
}

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
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;

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
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;
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

int uretprobe_event_handler(struct uretprobe_instance *probe, struct pt_regs *regs, struct us_ip *ip)
{
	int retval = regs_return_value(regs);
	unsigned long addr = (unsigned long)ip->jprobe.up.kp.addr;

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

int register_usprobe(struct task_struct *task, struct us_ip *ip)
{
	int ret = 0;

	if (ip->jprobe.entry == NULL) {
		ip->jprobe.entry = (void *)ujprobe_event_handler;
		DPRINTF("Set default event handler for %x\n", ip->offset);
	}

	if (ip->jprobe.pre_entry == NULL) {
		ip->jprobe.pre_entry = (uprobe_pre_entry_handler_t)ujprobe_event_pre_handler;
		DPRINTF("Set default pre handler for %x\n", ip->offset);
	}

	ip->jprobe.priv_arg = ip;
	ip->jprobe.up.task = task;
	ip->jprobe.up.sm = ip->page->file->procs->sm;
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

	if (ip->flag_retprobe) {
		// Mr_Nobody: comment for valencia
		if (ip->retprobe.handler == NULL) {
			ip->retprobe.handler = (uretprobe_handler_t)uretprobe_event_handler;
			DPRINTF("Set default ret event handler for %x\n", ip->offset);
		}

		ip->retprobe.priv_arg = ip;
		ip->retprobe.up.task = task;
		ip->retprobe.up.sm = ip->page->file->procs->sm;
		ret = dbi_register_uretprobe(&ip->retprobe);
		if (ret) {
			EPRINTF ("dbi_register_uretprobe() failure %d", ret);
			return ret;
		}
	}

	return 0;
}

int unregister_usprobe(struct task_struct *task, struct us_ip *ip)
{
	dbi_unregister_ujprobe(&ip->jprobe);

	if (ip->flag_retprobe) {
		dbi_unregister_uretprobe(&ip->retprobe);
	}

	return 0;
}
