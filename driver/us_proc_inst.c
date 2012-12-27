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

DEFINE_PER_CPU (us_proc_vtp_t *, gpVtp) = NULL;
DEFINE_PER_CPU (struct pt_regs *, gpCurVtpRegs) = NULL;

#if defined(CONFIG_MIPS)
#	define ARCH_REG_VAL(regs, idx)	regs->regs[idx]
#elif defined(CONFIG_ARM)
#	define ARCH_REG_VAL(regs, idx)	regs->uregs[idx]
#else
#	define ARCH_REG_VAL(regs, idx)	0
#	warning ARCH_REG_VAL is not implemented for this architecture. FBI will work improperly or even crash!!!
#endif // ARCH

unsigned long ujprobe_event_pre_handler (us_proc_ip_t * ip, struct pt_regs *regs);
void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);
int uretprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, us_proc_ip_t * ip);

static int register_usprobe(struct task_struct *task, us_proc_ip_t *ip, int atomic);
static int unregister_usprobe(struct task_struct *task, us_proc_ip_t * ip, int atomic, int no_rp2);

#include "new_dpf.h"

int us_proc_probes;

LIST_HEAD(proc_probes_list);

#ifdef SLP_APP
struct dentry *launchpad_daemon_dentry = NULL;
EXPORT_SYMBOL_GPL(launchpad_daemon_dentry);
#endif /* SLP_APP */

#ifdef ANDROID_APP
unsigned long android_app_vma_start = 0;
unsigned long android_app_vma_end = 0;
struct dentry *app_process_dentry = NULL;
#endif /* ANDROID_APP */

#ifdef __ANDROID
struct dentry *libdvm_dentry = NULL;
/* Defines below are for libdvm.so with md5sum:
 * 5941c87b49198368e7db726c2977bf1d */
#define LIBDVM_ENTRY 0x30a64
#define LIBDVM_RETURN 0x30bdc
#endif /* __ANDROID */



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

struct proc_probes *get_proc_probes_by_task(struct task_struct *task)
{
	struct proc_probes *proc_p, *tmp;

	if (!is_libonly()) {
		if (task != current) {
			printk("ERROR get_proc_probes_by_task: \'task != current\'\n");
			return NULL;
		}

		return us_proc_info.pp;
	}

	list_for_each_entry_safe(proc_p, tmp, &proc_probes_list, list) {
		if (proc_p->tgid == task->tgid) {
			return proc_p;
		}
	}

	return NULL;
}

void add_proc_probes(struct task_struct *task, struct proc_probes *proc_p)
{
	list_add_tail(&proc_p->list, &proc_probes_list);
}

struct proc_probes *get_proc_probes_by_task_or_new(struct task_struct *task)
{
	struct proc_probes *proc_p = get_proc_probes_by_task(task);
	if (proc_p == NULL) {
		proc_p = proc_p_copy(us_proc_info.pp, task);
		add_proc_probes(task, proc_p);
	}

	return proc_p;
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

#ifdef __ANDROID
void find_libdvm_for_task(struct task_struct *task, inst_us_proc_t *info)
{
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = NULL;

	mm = get_task_mm(task);
	if (mm) {
		vma = mm->mmap;
		while (vma) {
			if (vma->vm_file) {
				if (vma->vm_file->f_dentry == libdvm_dentry) {
					info->libdvm_start = vma->vm_start;
					info->libdvm_end = vma->vm_end;
					break;
				}
			}
			vma = vma->vm_next;
		}
		mmput(mm);
	}
}
#endif /* __ANDROID */

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

static int find_task_by_path (const char *path, struct task_struct **p_task, struct list_head *tids)
{
	int found = 0;
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct dentry *dentry = dentry_by_path(path);

	*p_task = 0;

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
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
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


static void us_vtp_event_pre_handler (us_proc_vtp_t * vtp, struct pt_regs *regs)
{
	__get_cpu_var(gpVtp) = vtp;
	__get_cpu_var(gpCurVtpRegs) = regs;
}

static void us_vtp_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	us_proc_vtp_t *vtp = __get_cpu_var(gpVtp);
#if !defined(CONFIG_X86)
	struct pt_regs *regs = __get_cpu_var(gpCurVtpRegs);
#endif
	char fmt[4];
	unsigned long vaddr;
	long ival;
	char cval, *sval;
	us_proc_vtp_data_t *vtp_data;
unsigned long ll;
	fmt[0] = 'p';
	fmt[3] = 0;
	fmt[2] = 's';

	list_for_each_entry_rcu (vtp_data, &vtp->list, list) {
		//		DPRINTF ("[%d]proc %s(%d): %lx", nCount++, current->comm, current->pid, vtp->addr);
		fmt[1] = vtp_data->type;
		if (vtp_data->reg == -1)
			vaddr = vtp_data->off;
		else
			vaddr = ARCH_REG_VAL (regs, vtp_data->reg) + vtp_data->off;
		//		DPRINTF ("VTP type '%c'", vtp_data->type);
		switch (vtp_data->type)
		{
			case 'd':
			case 'x':
			case 'p':
				if (read_proc_vm_atomic (current, vaddr, &ival, sizeof (ival)) < sizeof (ival))
					EPRINTF ("failed to read vm of proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
				else
					pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, ival, vtp_data->name);
				break;
			case 'f':
				if (read_proc_vm_atomic (current, vaddr, &ival, sizeof (ival)) < sizeof (ival))
					EPRINTF ("failed to read vm of proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
				else
					pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, ival, vtp_data->name);
				break;
			case 'c':
				if (read_proc_vm_atomic (current, vaddr, &cval, sizeof (cval)) < sizeof (cval))
					EPRINTF ("failed to read vm of proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
				else
					pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, cval, vtp_data->name);
				break;
			case 's':
				if (current->active_mm) {
					struct page *page;
					struct vm_area_struct *vma;
					void *maddr;
					int len;
					if (get_user_pages_atomic (current, current->active_mm, vaddr, 1, 0, 1, &page, &vma) <= 0) {
						EPRINTF ("get_user_pages_atomic failed for proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
						break;
					}
					maddr = kmap_atomic (page, KM_USER0);
					len = strlen (maddr + (vaddr & ~PAGE_MASK));
					sval = kmalloc (len + 1, GFP_KERNEL);
					if (!sval)
						EPRINTF ("failed to alloc memory for string in proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
					else {
						copy_from_user_page (vma, page, vaddr, sval, maddr + (vaddr & ~PAGE_MASK), len + 1);
						pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, sval,  vtp_data->name);
						kfree (sval);
					}
					kunmap_atomic (maddr, KM_USER0);
					page_cache_release (page);
				}
				else
					EPRINTF ("task %s/%u has no mm!", current->comm, current->pid);
				break;
			default:
				EPRINTF ("unknown variable type '%c'", vtp_data->type);
		}
	}
	dbi_uprobe_return ();
}

static int install_mapped_ips (struct task_struct *task, inst_us_proc_t* task_inst_info, int atomic)
{
	struct vm_area_struct *vma;
	int i, k, err;
	unsigned long addr;
	unsigned int old_ips_count, old_vtps_count;
	struct task_struct *t;
	struct mm_struct *mm;

	mm = atomic ? task->active_mm : get_task_mm (task);
	if (!mm) {
		return task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count;
	}
	old_ips_count = task_inst_info->unres_ips_count;
	old_vtps_count = task_inst_info->unres_vtps_count;
	if(!atomic)
		down_read (&mm->mmap_sem);
	vma = mm->mmap;
	while (vma) {
		// skip non-text section
#ifndef __ANDROID
		if (vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC) || !vma->vm_file || (vma->vm_flags & VM_ACCOUNT) ||
			!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) ||
			!(vma->vm_flags & (VM_READ | VM_MAYREAD))) {
#else // __ANDROID
		if (vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC) || !vma->vm_file) {
#endif // __ANDROID
			vma = vma->vm_next;
			continue;
		}
		/**
		 * After process was forked, some time it inherits parent process environment.
		 * We need to renew instrumentation when we detect that process gets own environment.
		 */
		for (i = 0; i < task_inst_info->libs_count; i++) {
//			struct path tmp_path;
//			tmp_path.dentry = task_inst_info->p_libs[i].m_f_dentry;
//			tmp_path.mnt = task_inst_info->p_libs[i].m_vfs_mount;
//			char* p_path = d_path ( &tmp_path, path_buffer, 255 );
//			DPRINTF("f_dentry:%x m_f_dentry:%x path:%s", vma->vm_file->f_dentry,
//				task_inst_info->p_libs[i].m_f_dentry, p_path );

			//TODO: test - try to instrument non-existing libs
			if (vma->vm_file->f_dentry == task_inst_info->p_libs[i].m_f_dentry) {
//				DPRINTF("vm_flags:%x loaded:%x ips_count:%d vtps_count:%d",
//						vma->vm_flags, task_inst_info->p_libs[i].loaded,
//						task_inst_info->p_libs[i].ips_count, task_inst_info->p_libs[i].vtps_count );
				if (!task_inst_info->p_libs[i].loaded) {
//					DPRINTF("!VM_EXECUTABLE && !loaded");
					char *p;
					int app_flag = (vma->vm_file->f_dentry == task_inst_info->m_f_dentry);
					DPRINTF ("post dyn lib event %s/%s", current->comm, task_inst_info->p_libs[i].path);
					// if we installed something, post library info for those IPs
					p = strrchr(task_inst_info->p_libs[i].path, '/');
					if(!p)
						p = task_inst_info->p_libs[i].path;
					else
						p++;
					task_inst_info->p_libs[i].loaded = 1;
					task_inst_info->p_libs[i].vma_start = vma->vm_start;
					task_inst_info->p_libs[i].vma_end = vma->vm_end;
					task_inst_info->p_libs[i].vma_flag = vma->vm_flags;
					pack_event_info (DYN_LIB_PROBE_ID, RECORD_ENTRY, "dspdd",
							task->tgid, p, vma->vm_start, vma->vm_end-vma->vm_start, app_flag);
				}
				for (k = 0; k < task_inst_info->p_libs[i].ips_count; k++) {
					DPRINTF("ips_count current:%d", k);
					if (!task_inst_info->p_libs[i].p_ips[k].installed) {
						DPRINTF("!installed");
						addr = task_inst_info->p_libs[i].p_ips[k].offset;
						addr += vma->vm_start;
						if (page_present (mm, addr)) {
							DPRINTF ("pid %d, %s sym is loaded at %lx/%lx.",
								task->pid, task_inst_info->p_libs[i].path,
								task_inst_info->p_libs[i].p_ips[k].offset, addr);
							task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr = (kprobe_opcode_t *) addr;
							task_inst_info->p_libs[i].p_ips[k].retprobe.kp.addr = (kprobe_opcode_t *) addr;
							task_inst_info->unres_ips_count--;
							err = register_usprobe(task, &task_inst_info->p_libs[i].p_ips[k], atomic);
							if (err != 0) {
								DPRINTF ("failed to install IP at %lx/%p. Error %d!",
									task_inst_info->p_libs[i].p_ips[k].offset,
									task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr, err);
							}
						}
					}
				}
				for (k = 0; k < task_inst_info->p_libs[i].vtps_count; k++) {
					DPRINTF("vtps_count current:%d", k);
					if (!task_inst_info->p_libs[i].p_vtps[k].installed) {
						DPRINTF("!installed");
						addr = task_inst_info->p_libs[i].p_vtps[k].addr;
						if (!(vma->vm_flags & VM_EXECUTABLE))
							addr += vma->vm_start;
						if (page_present (mm, addr)) {
							DPRINTF ("pid %d, %s sym is loaded at %lx/%lx.",
								task->pid, task_inst_info->p_libs[i].path,
								task_inst_info->p_libs[i].p_ips[k].offset, addr);
							task_inst_info->p_libs[i].p_vtps[k].jprobe.kp.tgid = task_inst_info->tgid;
							task_inst_info->p_libs[i].p_vtps[k].jprobe.kp.addr = (kprobe_opcode_t *) addr;
							task_inst_info->p_libs[i].p_vtps[k].jprobe.entry = (kprobe_opcode_t *) us_vtp_event_handler;
							task_inst_info->p_libs[i].p_vtps[k].jprobe.pre_entry = (kprobe_pre_entry_handler_t) us_vtp_event_pre_handler;
							task_inst_info->p_libs[i].p_vtps[k].jprobe.priv_arg = &task_inst_info->p_libs[i].p_vtps[k];
							task_inst_info->p_libs[i].p_vtps[k].installed = 1;
							task_inst_info->unres_vtps_count--;
							err = dbi_register_ujprobe(task, &task_inst_info->p_libs[i].p_vtps[k].jprobe, atomic);
							if ( err != 0 ) {
								EPRINTF ("failed to install VTP at %p. Error %d!",
										task_inst_info->p_libs[i].p_vtps[k].jprobe.kp.addr, err);
							}
						}
					}
				}
			}
		}
#ifdef __ANDROID
		if (is_java_inst_enabled()
		    && vma->vm_file->f_dentry == libdvm_dentry) {
			us_proc_ip_t *entp = &task_inst_info->libdvm_entry_ip;
			if (!entp->installed
			    && task_inst_info->libdvm_start) {
				unsigned long addr = LIBDVM_ENTRY + task_inst_info->libdvm_start;
				if (page_present(mm, addr)) {
					entp->jprobe.kp.tgid = task->tgid;
					entp->jprobe.pre_entry = ujprobe_event_pre_handler;
					entp->jprobe.entry = ujprobe_event_handler;
					entp->jprobe.priv_arg = entp;
					entp->jprobe.kp.addr = addr;
					entp->retprobe.kp.tgid = task->tgid;
					entp->retprobe.handler = uretprobe_event_handler;
					entp->retprobe.priv_arg = entp;
					entp->retprobe.kp.addr = addr;
					err = register_usprobe(task, mm, entp, atomic, 0);
					if (err != 0) {
						DPRINTF("failed to install IP at %p", addr);
					}
				}
				entp->installed = 1;
			}
			us_proc_ip_t *retp = &task_inst_info->libdvm_return_ip;
			if (!retp->installed
			    && task_inst_info->libdvm_start) {
				unsigned long addr = LIBDVM_RETURN + task_inst_info->libdvm_start;
				if (page_present(mm, addr)) {
					retp->jprobe.kp.tgid = task->tgid;
					retp->jprobe.pre_entry = ujprobe_event_pre_handler;
					retp->jprobe.entry = ujprobe_event_handler;
					retp->jprobe.priv_arg = retp;
					retp->jprobe.kp.addr = addr;
					retp->retprobe.kp.tgid = task->tgid;
					retp->retprobe.handler = uretprobe_event_handler;
					retp->retprobe.priv_arg = retp;
					retp->retprobe.kp.addr = addr;
					err = register_usprobe(task, mm, retp, atomic, 0);
					if (err != 0) {
						DPRINTF("failed to install IP at %p", addr);
					}
				}
				retp->installed = 1;
			}
		}
#endif /* __ANDROID */
		vma = vma->vm_next;
	}

	if (!atomic) {
		up_read (&mm->mmap_sem);
		mmput (mm);
	}
	return task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count;
}

static void set_mapping_file(struct file_probes *file_p,
		const struct proc_probes *proc_p,
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
			struct proc_probes *proc_p = get_proc_probes_by_task(task);
			struct probe_data pd = {
					.offset = offset_addr,
					.pre_handler = pre_handler,
					.jp_handler = jp_handler,
					.rp_handler = rp_handler,
					.flag_retprobe = 1
			};

			struct file_probes *file_p = proc_p_find_file_p_by_dentry(proc_p, name, dentry);
			struct page_probes *page_p = get_page_p(file_p, offset_addr);
			us_proc_ip_t *ip = page_p_find_ip(page_p, offset_addr & ~PAGE_MASK);

			if (!file_p->loaded) {
				set_mapping_file(file_p, proc_p, task, vma);
				file_p->loaded = 1;
			}

			if (ip == NULL) {
				struct file_probes *file_p = proc_p_find_file_p_by_dentry(proc_p, name, dentry);
				file_p_add_probe(file_p, &pd);

				/* if addr mapping, that probe install, else it be installed in do_page_fault handler */
				if (page_present(mm, addr)) {
					ip = page_p_find_ip(page_p, offset_addr & ~PAGE_MASK);
					set_ip_kp_addr(ip, page_p, file_p);

					// TODO: error
					ret = register_usprobe_my(task, ip);
					if (ret == 0) {
						page_p_installed(page_p);
					} else {
						printk("ERROR install_otg_ip: ret=%d\n", ret);
					}
				}
			}

			put_page_p(page_p);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(install_otg_ip);


static int uninstall_mapped_ips (struct task_struct *task,  inst_us_proc_t* task_inst_info, int atomic)
{
	int i, k, err;

	for (i = 0; i < task_inst_info->libs_count; i++)
	{
		DPRINTF ("clear lib %s.", task_inst_info->p_libs[i].path);
		for (k = 0; k < task_inst_info->p_libs[i].ips_count; k++)
		{
			if (task_inst_info->p_libs[i].p_ips[k].installed)
			{
				DPRINTF ("remove IP at %p.", task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr);
				err = unregister_usprobe (task, &task_inst_info->p_libs[i].p_ips[k], atomic, 0);
				if (err != 0)
				{
					EPRINTF ("failed to uninstall IP at %p. Error %d!", task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr, err);
					continue;
				}
				task_inst_info->unres_ips_count++;
			}
		}
		for (k = 0; k < task_inst_info->p_libs[i].vtps_count; k++)
		{
			if (task_inst_info->p_libs[i].p_vtps[k].installed)
			{
				dbi_unregister_ujprobe (task, &task_inst_info->p_libs[i].p_vtps[k].jprobe, atomic);
				task_inst_info->unres_vtps_count++;
				task_inst_info->p_libs[i].p_vtps[k].installed = 0;
			}
		}
		task_inst_info->p_libs[i].loaded = 0;
	}
#ifdef __ANDROID
	if (is_java_inst_enabled()) {
		us_proc_ip_t *entp = &task_inst_info->libdvm_entry_ip;
		if (entp->installed) {
			unregister_usprobe(task, entp, atomic);
			entp->installed = 0;
		}
		us_proc_ip_t *retp = &task_inst_info->libdvm_return_ip;
		if (retp->installed) {
			unregister_usprobe(task, retp, atomic);
			retp->installed = 0;
		}
	}
#endif /* __ANDROID */

	DPRINTF ("Ures IPs  %d.", task_inst_info->unres_ips_count);
	DPRINTF ("Ures VTPs %d.", task_inst_info->unres_vtps_count);
	return 0;
}

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

static int uninstall_us_proc_probes(struct task_struct *task, struct proc_probes *proc_p, enum US_FLAGS flag);

int deinst_usr_space_proc (void)
{
	int iRet = 0, found = 0;
	struct task_struct *task = 0;
	inst_us_proc_t *task_inst_info = NULL;

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
		struct proc_probes *proc_p;

		for_each_process(task)	{
			proc_p = get_proc_probes_by_task(task);
			if (proc_p) {
				int ret = uninstall_us_proc_probes(task, proc_p, US_UNREGS_PROBE);
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

static void install_proc_probes(struct task_struct *task, struct proc_probes *proc_p, int atomic);

int inst_usr_space_proc (void)
{
	int ret, i;
	struct task_struct *task = 0;

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

#ifdef __ANDROID
	if (is_java_inst_enabled()) {
		libdvm_dentry = dentry_by_path("/system/lib/libdvm.so");
		if (libdvm_dentry == NULL) {
			return -EINVAL;
		}

		memset(&us_proc_info.libdvm_entry_ip, 0, sizeof(us_proc_ip_t));
		memset(&us_proc_info.libdvm_return_ip, 0, sizeof(us_proc_ip_t));
		us_proc_info.libdvm_start = 0;
		us_proc_info.libdvm_end = 0;
	}
#endif /* __ANDROID */

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
			struct proc_probes *proc_p;

			if (task->flags & PF_KTHREAD){
				DPRINTF("ignored kernel thread %d\n",
					task->pid);
				continue;
			}

			proc_p = get_proc_probes_by_task_or_new(task);
			DPRINTF("trying process");
#ifdef __ANDROID
			if (is_java_inst_enabled()) {
				find_libdvm_for_task(task, task_inst_info);
			}
#endif /* __ANDROID */
			install_proc_probes(task, proc_p, 1);
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
#ifdef __ANDROID
			if (is_java_inst_enabled()) {
				find_libdvm_for_task(task, &us_proc_info);
			}
#endif /* __ANDROID */
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

extern storage_arg_t sa_dpf;

void do_page_fault_j_pre_code(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *task = current->group_leader;

	if (task->flags & PF_KTHREAD) {
		DPRINTF("ignored kernel thread %d\n", task->pid);
		return;
	}

	if (is_us_instrumentation()) {
		swap_put_entry_data((void *)addr, &sa_dpf);
	}
}
EXPORT_SYMBOL_GPL(do_page_fault_j_pre_code);


unsigned long imi_sum_time = 0;
unsigned long imi_sum_hit = 0;
EXPORT_SYMBOL_GPL (imi_sum_time);
EXPORT_SYMBOL_GPL (imi_sum_hit);

static void set_mapping_file(struct file_probes *file_p,
		const struct proc_probes *proc_p,
		const struct task_struct *task,
		const struct vm_area_struct *vma)
{
	int app_flag = (vma->vm_file->f_dentry == proc_p->dentry);
	char *p;
	// if we installed something, post library info for those IPs
	p = strrchr(file_p->path, '/');
	if(!p) {
		p = file_p->path;
	} else {
		p++;
	}

	file_p->vm_start = vma->vm_start;
	file_p->vm_end = vma->vm_end;

	pack_event_info(DYN_LIB_PROBE_ID, RECORD_ENTRY, "dspdd",
			task->tgid, p, vma->vm_start,
			vma->vm_end - vma->vm_start, app_flag);
}

void print_vma(struct mm_struct *mm);

static int register_us_page_probe(struct page_probes *page_p,
		const struct file_probes *file_p,
		const struct task_struct *task)
{
	int err = 0;
	us_proc_ip_t *ip;

	spin_lock(&page_p->lock);

	if (page_p_is_install(page_p)) {
		printk("page %x in %s task[tgid=%u, pid=%u] already installed\n",
				page_p->offset, file_p->dentry->d_iname, task->tgid, task->pid);
		print_vma(task->mm);
		return 0;
	}

	page_p_assert_install(page_p);
	page_p_set_all_kp_addr(page_p, file_p);

	list_for_each_entry(ip, &page_p->ip_list, list) {
		err = register_usprobe_my(task, ip);
		if (err != 0) {
			//TODO: ERROR
			return err;
		}
	}

	page_p_installed(page_p);

	spin_unlock(&page_p->lock);

	return 0;
}

static int unregister_us_page_probe(const struct task_struct *task,
		struct page_probes *page_p, enum US_FLAGS flag)
{
	int err = 0;
	us_proc_ip_t *ip;

	spin_lock(&page_p->lock);
	if (!page_p_is_install(page_p)) {
		spin_unlock(&page_p->lock);
		return 0;
	}

	list_for_each_entry(ip, &page_p->ip_list, list) {
		err = unregister_usprobe_my(task, ip, flag);
		if (err != 0) {
			//TODO: ERROR
			break;
		}
	}

	if (flag != US_DISARM) {
		page_p_uninstalled(page_p);
	}
	spin_unlock(&page_p->lock);

	return err;
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


static void install_page_probes(unsigned long page, struct task_struct *task, struct proc_probes *proc_p, int atomic)
{
	int lock;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	mm_read_lock(task, mm, atomic, lock);

	vma = find_vma(mm, page);
	if (vma && check_vma(vma)) {
		struct file_probes *file_p = proc_p_find_file_p(proc_p, vma);
		if (file_p) {
			struct page_probes *page_p;
			if (!file_p->loaded) {
				set_mapping_file(file_p, proc_p, task, vma);
				file_p->loaded = 1;
			}

			page_p = file_p_find_page_p_mapped(file_p, page);
			if (page_p) {
				register_us_page_probe(page_p, file_p, task);
			}
		}
	}

	mm_read_unlock(mm, atomic, lock);
}

static void install_file_probes(struct task_struct *task, struct mm_struct *mm, struct file_probes *file_p)
{
	struct page_probes *page_p = NULL;
	struct hlist_node *node = NULL;
	struct hlist_head *head = NULL;
	int i, table_size = (1 << file_p->page_probes_hash_bits);

	for (i = 0; i < table_size; ++i) {
		head = &file_p->page_probes_table[i];
		hlist_for_each_entry_rcu(page_p, node, head, hlist) {
			if (page_present(mm, page_p->offset)) {
				register_us_page_probe(page_p, file_p, task);
			}
		}
	}
}

static void install_proc_probes(struct task_struct *task, struct proc_probes *proc_p, int atomic)
{
	int lock;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	mm_read_lock(task, mm, atomic, lock);

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (check_vma(vma)) {
			struct file_probes *file_p = proc_p_find_file_p(proc_p, vma);
			if (file_p) {
				if (!file_p->loaded) {
					set_mapping_file(file_p, proc_p, task, vma);
					file_p->loaded = 1;
				}

				install_file_probes(task, mm, file_p);
			}
		}
	}

	mm_read_unlock(mm, atomic, lock);
}

static int check_install_pages_in_file(struct task_struct *task, struct file_probes *file_p)
{
	int i;
	int table_size = (1 << file_p->page_probes_hash_bits);
	struct page_probes *page_p;
	struct hlist_node *node, *tmp;
	struct hlist_head *head;

	for (i = 0; i < table_size; ++i) {
		head = &file_p->page_probes_table[i];
		hlist_for_each_entry_safe (page_p, node, tmp, head, hlist) {
			if (page_p->install) {
				return 1;
			}
		}
	}

	return 0;
}

static int unregister_us_file_probes(struct task_struct *task, struct file_probes *file_p, enum US_FLAGS flag)
{
	int i, err = 0;
	int table_size = (1 << file_p->page_probes_hash_bits);
	struct page_probes *page_p;
	struct hlist_node *node, *tmp;
	struct hlist_head *head;

	for (i = 0; i < table_size; ++i) {
		head = &file_p->page_probes_table[i];
		hlist_for_each_entry_safe (page_p, node, tmp, head, hlist) {
			err = unregister_us_page_probe(task, page_p, flag);
			if (err != 0) {
				// TODO: ERROR
				return err;
			}
		}
	}

	if (flag != US_DISARM) {
		file_p->loaded = 0;
	}

	return err;
}

static int uninstall_us_proc_probes(struct task_struct *task, struct proc_probes *proc_p, enum US_FLAGS flag)
{
	int err;
	struct file_probes *file_p;

	list_for_each_entry_rcu(file_p, &proc_p->file_list, list) {
		err = unregister_us_file_probes(task, file_p, flag);
		if (err != 0) {
			// TODO:
			return err;
		}
	}

	return err;
}

static pid_t find_proc_by_task(const struct task_struct *task, const struct dentry *dentry)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = task->active_mm;
	if (mm == NULL) {
		return 0;
	}

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
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
	struct vm_area_struct *vma = 0;
	struct proc_probes *proc_p = NULL;
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
		proc_p = get_proc_probes_by_task_or_new(task);
	} else {
		// find task
		if (us_proc_info.tgid == 0) {
			pid_t tgid = find_proc_by_task(task, us_proc_info.m_f_dentry);
			if (tgid) {
				us_proc_info.tgid = gl_nNotifyTgid = tgid;
			}
		}

		if (us_proc_info.tgid == task->tgid) {
			proc_p = us_proc_info.pp;
		}
	}

	if (proc_p) {
		unsigned long page = addr & PAGE_MASK;

#ifdef __ANDROID
		if (is_java_inst_enabled()) {
			find_libdvm_for_task(task, &us_proc_info);
		}
#endif /* __ANDROID */

		// overhead
		do_gettimeofday(&imi_tv1);
		install_page_probes(page, task, proc_p, 1);
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

int check_vma_area(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	return (vma->vm_start >= start && vma->vm_end <= end);
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
		char *name = vma->vm_file ? vma->vm_file->f_dentry->d_iname : "N/A";

		printk("### [%8x..%8x] %s%s%s pgoff=\'%8u\' %s\n",
				vma->vm_start, vma->vm_end, x, r, w, vma->vm_pgoff, name);
	}
	printk("### print_vma:  END\n");
}

static int remove_unmap_probes(struct task_struct *task, struct proc_probes *proc_p, unsigned long start, size_t len)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	unsigned long end, pointer, step;

	if ((start & ~PAGE_MASK) || start > TASK_SIZE || len > TASK_SIZE - start) {
		return -EINVAL;
	}

	if ((len = PAGE_ALIGN(len)) == 0) {
		return -EINVAL;
	}

	vma = find_vma(mm, start);
	if (vma && check_vma(vma)) {
		struct file_probes *file_p;
		unsigned long end = start + len;

		file_p = proc_p_find_file_p(proc_p, vma);
		if (file_p) {
			if (vma->vm_start == start || vma->vm_end == end) {
				unregister_us_file_probes(task, file_p, US_NOT_RP2);
				file_p->loaded = 0;
			} else {
				unsigned long page;
				struct page_probes *page_p;

				for (page = vma->vm_start; page < vma->vm_end; page += PAGE_SIZE) {
					page_p = file_p_find_page_p_mapped(file_p, page);
					if (page_p) {
						unregister_us_page_probe(task, page_p, US_NOT_RP2);
					}
				}

				if (check_install_pages_in_file(task, file_p)) {
					file_p->loaded = 0;
				}
			}
		}
	}

	return 0;
}

void do_munmap_probe_pre_code(struct mm_struct *mm, unsigned long start, size_t len)
{
	struct proc_probes *proc_p = NULL;
	struct task_struct *task = current;

	//if user-space instrumentation is not set
	if (!is_us_instrumentation()) {
		return;
	}

	if (is_libonly()) {
		proc_p = get_proc_probes_by_task(task);
	} else {
		if (task->tgid == us_proc_info.tgid) {
			proc_p = us_proc_info.pp;
		}
	}

	if (proc_p) {
		if (remove_unmap_probes(task, proc_p, start, len)) {
			printk("ERROR do_munmap: start=%x, len=%x\n", start, len);
		}
	}
}
EXPORT_SYMBOL_GPL(do_munmap_probe_pre_code);

void mm_release_probe_pre_code(void)
{
	struct task_struct *task = current;
	struct proc_probes *proc_p = NULL;

	if (!is_us_instrumentation() || task->tgid != task->pid) {
		return;
	}

	if (is_libonly()) {
		proc_p = get_proc_probes_by_task(task);
	} else {
		if (task->tgid == us_proc_info.tgid) {
			proc_p = get_proc_probes_by_task(task);
			us_proc_info.tgid = 0;
		}
	}

	if (proc_p) {
		int ret = uninstall_us_proc_probes(task, proc_p, US_NOT_RP2);
		if (ret != 0) {
			EPRINTF ("failed to uninstall IPs (%d)!", ret);
		}

		dbi_unregister_all_uprobes(task, 1);
	}
}
EXPORT_SYMBOL_GPL(mm_release_probe_pre_code);


static void recover_child(struct task_struct *child_task, struct proc_probes *proc_p)
{
	uninstall_us_proc_probes(child_task, proc_p, US_DISARM);
}

static void rm_uprobes_child(struct task_struct *new_task)
{
	if (is_libonly()) {
		struct proc_probes *proc_p = get_proc_probes_by_task(current);
		if(proc_p) {
			recover_child(new_task, proc_p);
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


DEFINE_PER_CPU (us_proc_ip_t *, gpCurIp) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpCurIp);
DEFINE_PER_CPU(struct pt_regs *, gpUserRegs) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpUserRegs);


unsigned long ujprobe_event_pre_handler (us_proc_ip_t * ip, struct pt_regs *regs)
{
	__get_cpu_var (gpCurIp) = ip;
	__get_cpu_var (gpUserRegs) = regs;
	return 0;
}

#ifdef __ANDROID
int handle_java_event(unsigned long addr)
{
	unsigned long start = 0;
	struct pt_regs *regs = __get_cpu_var(gpUserRegs);

	if (is_libonly()) {
		/* TODO: some stuff here */
	} else {
		start = us_proc_info.libdvm_start;
	}
	unsigned long end = us_proc_info.libdvm_end;

	if (addr == start + LIBDVM_ENTRY) {
		unsigned long *p_met = (unsigned long *)regs->ARM_r0;
		char *met_name = p_met ? (char *)(p_met[4]) : 0;
		unsigned long *p_cl = p_met ? (unsigned long *)p_met[0] : 0;
		char *cl_name = p_cl ? (char *)(p_cl[6]) : 0;
		if (!cl_name || !met_name) {
			EPRINTF("warn: class name or method name null\n");
		} else {
			pack_event_info(JAVA_PROBE_ID, RECORD_ENTRY, "pss", addr, cl_name, met_name);
		}
		dbi_uprobe_return ();
		return 1;
	}

	if (addr == start + LIBDVM_RETURN) {
		unsigned long *p_th = (unsigned long *)regs->ARM_r6;
		unsigned long *p_st = p_th;
		unsigned long *p_met = p_st ? (unsigned long *)p_st[2] : 0;
		char *met_name = p_met ? (char *)(p_met[4]) : 0;
		unsigned long *p_cl = p_met ? (unsigned long *)p_met[0] : 0;
		char *cl_name = p_cl ? (char *)(p_cl[6]) : 0;
		if (!cl_name || !met_name) {
			EPRINTF("warn: class name or method name null\n");
		} else {
			pack_event_info(JAVA_PROBE_ID, RECORD_RET, "pss", addr, cl_name, met_name);
		}
		dbi_uprobe_return ();
		return 1;
	}

	return 0;
}
#endif /* __ANDROID */

void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	us_proc_ip_t *ip = __get_cpu_var (gpCurIp);
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;

#ifdef __ANDROID
	if (is_java_inst_enabled() && handle_java_event(addr)) {
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

void send_plt(us_proc_ip_t *ip)
{
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;
	struct vm_area_struct *vma = find_vma(current->mm, addr);
	if (vma && check_vma(vma)) {
		char *name = NULL;
		unsigned long real_addr;
		unsigned long real_got = ip->got_addr;
		if (!(vma->vm_flags & VM_EXECUTABLE)) {
			real_got += + vma->vm_start;
		}

		if (!read_proc_vm_atomic(current, real_got, &real_addr, sizeof(real_addr))) {
			printk("Failed to read got %p at memory address %p!\n", ip->got_addr, real_got);
			return;
		}

		vma = find_vma(current->mm, real_addr);
		if (vma && (vma->vm_start <= real_addr) && (vma->vm_end > real_addr)) {
			name = vma->vm_file ? vma->vm_file->f_dentry->d_iname : NULL;
		} else {
			printk("Failed to get vma, includes %x address\n", real_addr);
			return;
		}

		if (name) {
			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppsp", addr, real_addr, name, real_addr - vma->vm_start);
		} else {
			pack_event_info(PLT_ADDR_PROBE_ID, RECORD_RET, "ppp", addr, real_addr, real_addr - vma->vm_start);
		}
	}
}

int uretprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, us_proc_ip_t * ip)
{
	int retval = regs_return_value(regs);
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;

//	find_plt_address(addr);

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

static int register_usprobe(struct task_struct *task, us_proc_ip_t *ip, int atomic)
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
		DPRINTF ("dbi_register_ujprobe() failure %d", ret);
		return ret;
	}

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

	ip->installed = 1;

	return 0;
}

static int unregister_usprobe(struct task_struct *task, us_proc_ip_t * ip, int atomic, int not_rp2)
{
	dbi_unregister_ujprobe(task, &ip->jprobe, atomic);

	if (ip->flag_retprobe) {
		dbi_unregister_uretprobe(task, &ip->retprobe, atomic, not_rp2);
	}

	ip->installed = 0;

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

unsigned long get_ret_addr(struct task_struct *task, us_proc_ip_t *ip)
{
	unsigned long retaddr = 0;
	struct hlist_node *item, *tmp_node;
	struct kretprobe_instance *ri;

	if (ip) {
		hlist_for_each_safe (item, tmp_node, &ip->retprobe.used_instances) {
			ri = hlist_entry (item, struct kretprobe_instance, uflist);

			if (ri->task && ri->task->pid == task->pid &&
					ri->task->tgid == task->tgid)
				retaddr = (unsigned long)ri->ret_addr;
		}
	}

	if (retaddr)
		return retaddr;
	else
		return dbi_get_ret_addr(task_pt_regs(task));
}
EXPORT_SYMBOL_GPL(get_ret_addr);

