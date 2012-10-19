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

unsigned long (*dbi_ujprobe_event_pre_handler_custom_p)
(us_proc_ip_t *, struct pt_regs *) = NULL;
EXPORT_SYMBOL(dbi_ujprobe_event_pre_handler_custom_p);
void (*dbi_ujprobe_event_handler_custom_p)(void) = NULL;
EXPORT_SYMBOL(dbi_ujprobe_event_handler_custom_p);
int (*dbi_uretprobe_event_handler_custom_p)
(struct kretprobe_instance *, struct pt_regs *, us_proc_ip_t *) = NULL;
EXPORT_SYMBOL(dbi_uretprobe_event_handler_custom_p);

unsigned long ujprobe_event_pre_handler (us_proc_ip_t * ip, struct pt_regs *regs);
void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6);
int uretprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, us_proc_ip_t * ip);

static int register_usprobe (struct task_struct *task, struct mm_struct *mm, us_proc_ip_t * ip, int atomic, kprobe_opcode_t * islot);
static int unregister_usprobe (struct task_struct *task, us_proc_ip_t * ip, int atomic);

int us_proc_probes;

struct task_inst_info_node {
	struct list_head      plist;
	inst_us_proc_t *      task_inst_info;
	int                   tgid;
};
LIST_HEAD(task_inst_info_list);

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

us_proc_otg_ip_t *find_otg_probe(unsigned long addr)
{
	us_proc_otg_ip_t *p;

	list_for_each_entry_rcu (p, &otg_us_proc_info, list) {
		if (p->ip.offset == addr) {
			return p;
		}
	}

	return NULL;
}

int add_otg_probe_to_list(unsigned long addr, us_proc_otg_ip_t **pprobe)
{
	us_proc_otg_ip_t *new_probe;
	us_proc_otg_ip_t *probe;

	if (pprobe) {
		*pprobe = NULL;
	}
	/* check if such probe does already exist */
	probe = find_otg_probe(addr);
	if (probe) {
		return 1;
	}

	new_probe = kmalloc(sizeof(us_proc_otg_ip_t), GFP_KERNEL);
	if (!new_probe)	{
		EPRINTF ("no memory for new probe!");
		return -ENOMEM;
	}
	memset(new_probe,0, sizeof(us_proc_otg_ip_t));

	new_probe->ip.offset = addr;
	new_probe->ip.jprobe.kp.addr =
		new_probe->ip.retprobe.kp.addr = (kprobe_opcode_t *)addr;
	new_probe->ip.jprobe.priv_arg =
		new_probe->ip.retprobe.priv_arg = new_probe;

	INIT_LIST_HEAD(&new_probe->list);
	list_add_rcu(&new_probe->list, &otg_us_proc_info);

	if (pprobe) {
		*pprobe = new_probe;
	}
	return 0;
}

int remove_otg_probe_from_list(unsigned long addr)
{
	us_proc_otg_ip_t *p;

	//check if such probe does exist
	p = find_otg_probe(addr);
	if (!p) {
		/* We do not care about it. Nothing bad. */
		return 0;
	}

	list_del_rcu(&p->list);

	kfree (p);

	return 0;
}

/**
 * Prepare copy of instrumentation data for task
 * in case of library only instrumentation
 */

inst_us_proc_t* copy_task_inst_info (struct task_struct *task, inst_us_proc_t * task_inst_info)
{
	int i, j;
	kprobe_opcode_t *entry_save;
	kprobe_pre_entry_handler_t pre_entry_save;
	kretprobe_handler_t handler_save;

	inst_us_proc_t* copy_info = 0;

	int unres_ips_count = 0, unres_vtps_count = 0;

	copy_info = kmalloc (sizeof (inst_us_proc_t), GFP_ATOMIC);
	memset ((void *) copy_info, 0, sizeof (inst_us_proc_t));

	copy_info->path = task_inst_info->path;
	copy_info->m_f_dentry = NULL;

	copy_info->libs_count = task_inst_info->libs_count;
	copy_info->p_libs =
		kmalloc (task_inst_info->libs_count * sizeof (us_proc_lib_t), GFP_ATOMIC);

	if (!copy_info->p_libs) {
		DPRINTF ("No enough memory for copy_info->p_libs");
		return NULL;
	}
	memcpy (copy_info->p_libs, task_inst_info->p_libs,
			copy_info->libs_count * sizeof (us_proc_lib_t));

	for (i = 0; i < copy_info->libs_count; i++) {
		if (copy_info->p_libs[i].ips_count > 0)
		{
			unres_ips_count += copy_info->p_libs[i].ips_count;

			copy_info->p_libs[i].p_ips =
				kmalloc (copy_info->p_libs[i].ips_count * sizeof (us_proc_ip_t), GFP_ATOMIC);

			if (!copy_info->p_libs[i].p_ips) {
				DPRINTF ("No enough memory for copy_info->p_libs[i].p_ips");
				return NULL;
			}

			memcpy (copy_info->p_libs[i].p_ips, task_inst_info->p_libs[i].p_ips,
					copy_info->p_libs[i].ips_count * sizeof (us_proc_ip_t));
			for (j = 0; j < copy_info->p_libs[i].ips_count; j++) {
				// save handlers
				entry_save = copy_info->p_libs[i].p_ips[j].jprobe.entry;
				pre_entry_save = copy_info->p_libs[i].p_ips[j].jprobe.pre_entry;
				handler_save = copy_info->p_libs[i].p_ips[j].retprobe.handler;

				copy_info->p_libs[i].p_ips[j].installed = 0;
				memset(&copy_info->p_libs[i].p_ips[j].jprobe, 0, sizeof(struct jprobe));
				memset(&copy_info->p_libs[i].p_ips[j].retprobe, 0, sizeof(struct kretprobe));

				// restore handlers
				copy_info->p_libs[i].p_ips[j].jprobe.entry = entry_save;
				copy_info->p_libs[i].p_ips[j].jprobe.pre_entry = pre_entry_save;
				copy_info->p_libs[i].p_ips[j].retprobe.handler = handler_save;
			}

			unres_ips_count += copy_info->p_libs[i].ips_count;
		}

		if (copy_info->p_libs[i].vtps_count > 0) {
			unres_vtps_count += copy_info->p_libs[i].vtps_count;

			copy_info->p_libs[i].p_vtps =
				kmalloc (copy_info->p_libs[i].vtps_count * sizeof (us_proc_vtp_t), GFP_ATOMIC);

			if (!copy_info->p_libs[i].p_vtps) {
				DPRINTF ("No enough memory for copy_info->p_libs[i].p_vtps");
				return NULL;
			}

			memcpy (copy_info->p_libs[i].p_vtps, task_inst_info->p_libs[i].p_vtps,
					copy_info->p_libs[i].vtps_count * sizeof (us_proc_vtp_t));
			for (j = 0; j < copy_info->p_libs[i].vtps_count; j++) {
				copy_info->p_libs[i].p_vtps[j].installed = 0;
				memset (&copy_info->p_libs[i].p_vtps[j].jprobe, 0, sizeof(struct jprobe));
			}
			unres_vtps_count = copy_info->p_libs[i].vtps_count;
		}

		copy_info->p_libs[i].m_f_dentry = task_inst_info->p_libs[i].m_f_dentry;
		copy_info->p_libs[i].loaded = 0;
	}
	copy_info->unres_ips_count = unres_ips_count;
	copy_info->unres_vtps_count = unres_vtps_count;

	return copy_info;
}

inst_us_proc_t* get_task_inst_node(struct task_struct *task)
{
	struct task_inst_info_node *node, *tnode;

	list_for_each_entry_safe(node, tnode, &task_inst_info_list, plist)
	{
		if (node && task && node->tgid == task->tgid) {
			return node->task_inst_info;
		}
	}
	return NULL;
}

void put_task_inst_node(struct task_struct *task, inst_us_proc_t *task_inst_info)
{
	struct task_inst_info_node * node;

	node = kmalloc (sizeof(struct task_inst_info_node), GFP_ATOMIC);

	node->tgid = task->tgid;
	node->task_inst_info = task_inst_info;

	list_add_tail (&(node->plist), &task_inst_info_list);
}


void clear_task_inst_info(void)
{
	struct list_head *node, *tmp;

	list_for_each_safe(node, tmp, &task_inst_info_list)
		list_del(node);
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

static int find_task_by_path (const char *path, struct task_struct **p_task, struct list_head *tids)
{
	int found = 0;
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	struct path s_path;
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	struct nameidata nd;
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */

	*p_task = 0;

	/* find corresponding dir entry, this is also check for valid path */
	// TODO: test - try to instrument process with non-existing path
	// TODO: test - try to instrument process  with existing path and delete file just after start
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	if (kern_path(us_proc_info.path, LOOKUP_FOLLOW, &s_path) != 0) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	if (path_lookup(us_proc_info.path, LOOKUP_FOLLOW, &nd) != 0) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
		EPRINTF ("failed to lookup dentry for path %s!", path);
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
				if (vma->vm_file->f_dentry == nd.dentry) {
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
				if (vma->vm_file->f_dentry == s_path.dentry  ) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
				if (vma->vm_file->f_dentry == nd.path.dentry  ) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
#endif
					if (!*p_task) {
						*p_task = task;
						get_task_struct (task);
					}
						//break;
				}
#ifdef SLP_APP
				if (!*p_task) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
					if (is_slp_app_with_dentry(vma, nd.dentry)) {
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
					if (is_slp_app_with_dentry(vma, s_path.dentry)) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
					if (is_slp_app_with_dentry(vma, nd.path.dentry)) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
#endif
						*p_task = task;
						get_task_struct(task);
					}
				}
#endif /* SLP_APP */
#ifdef ANDROID_APP
				if (!*p_task) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
					if (is_android_app_with_dentry(vma, nd.dentry)) {
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
					if (is_android_app_with_dentry(vma, s_path.dentry)) {
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
					if (is_android_app_with_dentry(vma, nd.path.dentry)) {
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
#endif
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
	path_release (&nd);
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
	path_put (&s_path);
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	path_put (&nd.path);
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
#endif
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
	char fmt[3];
	unsigned long vaddr;
	long ival;
	char cval, *sval;
	us_proc_vtp_data_t *vtp_data;

	fmt[0] = 'p';
	fmt[2] = 0;

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
					pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, ival);
				break;
			case 'f':
				if (read_proc_vm_atomic (current, vaddr, &ival, sizeof (ival)) < sizeof (ival))
					EPRINTF ("failed to read vm of proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
				else
					pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, ival);
				break;
			case 'c':
				if (read_proc_vm_atomic (current, vaddr, &cval, sizeof (cval)) < sizeof (cval))
					EPRINTF ("failed to read vm of proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
				else
					pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, cval);
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
						pack_event_info (VTP_PROBE_ID, RECORD_ENTRY, fmt, vtp->jprobe.kp.addr, sval);
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
	us_proc_otg_ip_t *p;
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
							task_inst_info->p_libs[i].p_ips[k].installed = 1;
							task_inst_info->unres_ips_count--;
							err = register_usprobe (task, mm, &task_inst_info->p_libs[i].p_ips[k], atomic, 0);
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
							err = dbi_register_ujprobe (task, mm, &task_inst_info->p_libs[i].p_vtps[k].jprobe, atomic);
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
	list_for_each_entry_rcu (p, &otg_us_proc_info, list) {
		if (p->ip.installed) {
			continue;
		}
		rcu_read_lock();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
		t = find_task_by_pid(p->tgid);
#else
		t = pid_task(find_pid_ns(p->tgid, &init_pid_ns),
			     PIDTYPE_PID);
#endif
		if (t){
			get_task_struct(t);
		}
		rcu_read_unlock();
		if (!t) {
			DPRINTF("task for pid %d not found! Dead probe?",
				  p->tgid);
			continue;
		}
		if (!t->active_mm) {
			continue;
		}
		if (!page_present(t->active_mm, p->ip.offset)) {
			DPRINTF("Page isn't present for %p.",
				p->ip.offset);
			continue;
		}
		p->ip.installed = 1;
		err = register_usprobe(current, t->active_mm,
				       &p->ip, atomic, 0);
		if (err != 0) {
			DPRINTF("failed to install IP at %lx/%p. Error %d!",
				p->ip.offset,
				p->ip.jprobe.kp.addr, err);
			return err;
		}
		task_inst_info->unres_otg_ips_count--;
	}
	if (!atomic) {
		up_read (&mm->mmap_sem);
		mmput (mm);
	}
	return task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count;
}

static int install_otg_ip(unsigned long addr,
		      unsigned long pre_handler,
		      unsigned long jp_handler,
		      unsigned long rp_handler)
{
	int err;
	us_proc_otg_ip_t *pprobe;
	struct mm_struct *mm;

	inst_us_proc_t *task_inst_info = NULL;
	struct task_struct *task;

	/* Probe preparing */
	err = add_otg_probe_to_list(addr, &pprobe);
	if (err) {
		if (err == 1) {
			DPRINTF("OTG probe %p already installed.", addr);
			return 0;
		} else {
			DPRINTF("Failed to add new OTG probe, err=%d",err);
			return err;
		}
	}
	if (pre_handler) {
		pprobe->ip.jprobe.pre_entry =
			(kprobe_pre_entry_handler_t)pre_handler;
	} else {
		pprobe->ip.jprobe.pre_entry =
			(kprobe_pre_entry_handler_t)
			dbi_ujprobe_event_pre_handler_custom_p;

	}
	if (jp_handler) {
		pprobe->ip.jprobe.entry =
			(kprobe_opcode_t *)jp_handler;
	} else {
		pprobe->ip.jprobe.entry =
			(kprobe_opcode_t *)
			dbi_ujprobe_event_handler_custom_p;
	}
	if (rp_handler) {
		pprobe->ip.retprobe.handler =
			(kretprobe_handler_t)rp_handler;
	} else {
		pprobe->ip.retprobe.handler =
			(kretprobe_handler_t)
			dbi_uretprobe_event_handler_custom_p;
	}

	mm = get_task_mm(current);
	if (!page_present(mm, addr)) {
		DPRINTF("Page isn't present for %p.", addr);

		pprobe->tgid = current->tgid;
		task = current->group_leader;

		task_inst_info = get_task_inst_node(task);
		if (!task_inst_info)
		{
			task_inst_info = copy_task_inst_info(task, &us_proc_info);
			put_task_inst_node(task, task_inst_info);
		}
		us_proc_info.unres_otg_ips_count++;
		/* Probe will be installed in do_page_fault handler */
		return 0;
	}
	DPRINTF("Page present for %p.", addr);

	/* Probe installing */
	pprobe->tgid = current->tgid;
	pprobe->ip.installed = 1;
	err = register_usprobe(current, mm, &pprobe->ip, 1, 0);
	if (err != 0) {
		DPRINTF("failed to install IP at %lx/%p. Error %d!",
			 addr, pprobe->ip.jprobe.kp.addr, err);
		return err;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(install_otg_ip);


static int uninstall_mapped_ips (struct task_struct *task,  inst_us_proc_t* task_inst_info, int atomic)
{
	int i, k, err;
	us_proc_otg_ip_t *p;

	for (i = 0; i < task_inst_info->libs_count; i++)
	{
		DPRINTF ("clear lib %s.", task_inst_info->p_libs[i].path);
		for (k = 0; k < task_inst_info->p_libs[i].ips_count; k++)
		{
			if (task_inst_info->p_libs[i].p_ips[k].installed)
			{
				DPRINTF ("remove IP at %p.", task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr);
				err = unregister_usprobe (task, &task_inst_info->p_libs[i].p_ips[k], atomic);
				if (err != 0)
				{
					EPRINTF ("failed to uninstall IP at %p. Error %d!", task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr, err);
					continue;
				}
				task_inst_info->unres_ips_count++;
				task_inst_info->p_libs[i].p_ips[k].installed = 0;
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
	list_for_each_entry_rcu (p, &otg_us_proc_info, list) {
		if (!p->ip.installed) {
			continue;
		}
		DPRINTF("remove OTG IP at %p.",	p->ip.offset);
		err = unregister_usprobe(task, &p->ip, atomic);
		if (err != 0) {
			EPRINTF("failed to uninstall IP at %p. Error %d!",
				 p->ip.jprobe.kp.addr, err);
			continue;
		}
		p->ip.installed = 0;
	}

	DPRINTF ("Ures IPs  %d.", task_inst_info->unres_ips_count);
	DPRINTF ("Ures VTPs %d.", task_inst_info->unres_vtps_count);
	return 0;
}

void send_sig_jprobe_event_handler (int sig, struct siginfo *info, struct task_struct *t, struct sigpending *signals)
{
	int iRet, del = 0;
	struct task_struct *task;
	inst_us_proc_t *task_inst_info = NULL;

	//if user-space instrumentation is not set
	if (!us_proc_info.path)
	    return;

	if (sig != SIGKILL)
		return;

	if (!strcmp(us_proc_info.path,"*"))
	{
		task_inst_info = get_task_inst_node(t);
		if (task_inst_info)
		{
			iRet = uninstall_mapped_ips (t, task_inst_info, 1);
			if (iRet != 0)
				EPRINTF ("failed to uninstall IPs (%d)!", iRet);
			dbi_unregister_all_uprobes(t, 1);
			return;
		}
	}
	else
	{
		if (current->tgid != us_proc_info.tgid)
			return;
			del = 1;

		// look for another process with the same tgid
		rcu_read_lock ();
		for_each_process (task)
		{
			if ((task->pid != t->pid) && (task->tgid == us_proc_info.tgid))
			{
				del = 0;
				break;
			}
		}
		rcu_read_unlock ();
		if (del)
		{
			DPRINTF ("%s(%d) send_signal SIGKILL for the last target proc %s(%d)",
					current->comm, current->pid, t->comm, t->pid);
			iRet = uninstall_mapped_ips (t, &us_proc_info, 1);
			if (iRet != 0)
				EPRINTF ("failed to uninstall IPs (%d)!", iRet);
		}
	}
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

int deinst_usr_space_proc (void)
{
	int iRet = 0, found = 0;
	struct task_struct *task = 0;
	inst_us_proc_t *task_inst_info = NULL;

	//if user-space instrumentation is not set
	if (!us_proc_info.path)
		return 0;

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

	if (!strcmp(us_proc_info.path,"*"))
	{
		for_each_process (task)
		{
			task_inst_info = get_task_inst_node(task);
			if (task_inst_info)
			{
				iRet = uninstall_mapped_ips (task, task_inst_info, 1);
				if (iRet != 0)
					EPRINTF ("failed to uninstall IPs (%d)!", iRet);
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
			int i;
			// uninstall IPs
			iRet = uninstall_mapped_ips (task, &us_proc_info, 0);
			if (iRet != 0)
			EPRINTF ("failed to uninstall IPs %d!", iRet);
			put_task_struct (task);
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

static struct dentry *get_dentry(const char *path)
{
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
	return nd.dentry;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
	return nd.path.dentry;
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
	return st_path.dentry;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25) */
}

int inst_usr_space_proc (void)
{
	int ret, i;
	struct task_struct *task = 0;
	inst_us_proc_t *task_inst_info = NULL;

	//if user-space instrumentation is not set
	if (!us_proc_info.path)
		return 0;

	DPRINTF("User space instr");

#ifdef SLP_APP
	launchpad_daemon_dentry = get_dentry("/usr/bin/launchpad_preloading_preinitializing_daemon");
	if (launchpad_daemon_dentry == NULL) {
		return -EINVAL;
	}

#endif /* SLP_APP */

#ifdef ANDROID_APP
	app_process_dentry = get_dentry("/system/bin/app_process");
	if (app_process_dentry == NULL) {
		return -EINVAL;
	}

	android_app_vma_start = 0;
	android_app_vma_end = 0;
#endif /* ANDROID_APP */

#ifdef __ANDROID
	if (is_java_inst_enabled()) {
		libdvm_dentry = get_dentry("/system/lib/libdvm.so");
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

	if (!strcmp(us_proc_info.path,"*"))
	{
		clear_task_inst_info();
		for_each_process (task) {
			if (task->flags & PF_KTHREAD){
				DPRINTF("ignored kernel thread %d\n",
					task->pid);
				continue;
			}

			task_inst_info = get_task_inst_node(task);
			if (!task_inst_info) {
				task_inst_info =
					copy_task_inst_info(task,
							    &us_proc_info);
				put_task_inst_node(task, task_inst_info);
			}
			DPRINTF("trying process");
#ifdef __ANDROID
			if (is_java_inst_enabled()) {
				find_libdvm_for_task(task, task_inst_info);
			}
#endif /* __ANDROID */
			install_mapped_ips (task, task_inst_info, 1);
			//put_task_struct (task);
			task_inst_info = NULL;
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
			install_mapped_ips (task, &us_proc_info, 0);
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
	return 0;
}

#include "../../tools/gpmu/probes/entry_data.h"

extern storage_arg_t sa_dpf;

void do_page_fault_j_pre_code(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	swap_put_entry_data((void *)addr, &sa_dpf);

	unsigned long addr_page_0 = (addr / PAGE_SIZE) * PAGE_SIZE;
	unsigned long addr_page_1 = (addr >> PAGE_SHIFT) << PAGE_SHIFT;
	unsigned long addr_page_2 = addr & PAGE_MASK;

//	printk("\n### do_page_fault_j_pre_code: addr=%x, addr_page_0=%x, addr_page_1=%x, addr_page_2=%x\n",
//			addr, addr_page_0, addr_page_1, addr_page_2);
}
EXPORT_SYMBOL_GPL(do_page_fault_j_pre_code);


unsigned long imi_sum_time = 0;
unsigned long imi_sum_hit = 0;
EXPORT_SYMBOL_GPL (imi_sum_time);
EXPORT_SYMBOL_GPL (imi_sum_hit);




#include "new_dpf.h"

static void send_mapping_event(struct file_probes *file_p,
		const struct proc_probes *proc_p,
		const struct task_struct *task,
		const struct vm_area_struct *vma)
{
	if (!file_p->loaded) {
		int app_flag = (vma->vm_file->f_dentry == proc_p->dentry);
		char *p;
		// if we installed something, post library info for those IPs
		p = strrchr(file_p->path, '/');
		if(!p) {
			p = file_p->path;
		} else {
			p++;
		}
		file_p->loaded = 1;
		pack_event_info (DYN_LIB_PROBE_ID, RECORD_ENTRY, "dspdd",
				task->tgid, p, vma->vm_start, vma->vm_end-vma->vm_start, app_flag);
	}
}

static void register_us_page_probe(const struct page_probes *page_p,
		const struct file_probes *file_p,
		struct proc_probes *proc_p,
		const struct task_struct *task,
		const struct mm_struct *mm,
		const struct vm_area_struct *vma)
{
	int err;
	size_t i;

	send_mapping_event(file_p, proc_p, task, vma);

//	print_page_probes(page_p);
	page_p_set_all_kp_addr(page_p);

	for (i = 0; i < page_p->cnt_ip; ++i) {
		err = register_usprobe_my(task, mm, &page_p->ip[i]);
		if (err != 0) {
			//TODO: ERROR
		}
	}
}

static int check_vma(struct vm_area_struct *vma)
{
#ifndef __ANDROID
	return vma->vm_file && !(!(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_ACCOUNT) ||
			!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) ||
			!(vma->vm_flags & (VM_READ | VM_MAYREAD)));
#else // __ANDROID
	return vma->vm_file && !(vma->vm_pgoff != 0 || !(vma->vm_flags & VM_EXEC));
#endif // __ANDROID
}


static void install_page_probes(unsigned long page, struct task_struct *task, struct proc_probes *proc_p, unsigned long addr)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = get_task_mm(task);

	if (mm == NULL) {
		printk("#### ERRR install_page_probes\n");
		return;
	}

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, page);
	if (vma && check_vma(vma)) {
		struct file_probes *file_p = proc_p_find_file_p(proc_p, vma);
		if(file_p) {
			struct page_probes *page_p = file_p_find_page_p(file_p, page, vma->vm_start);
			if (page_p) {
				register_us_page_probe(page_p, file_p, proc_p, task, mm, vma);
			}
		}
	}

	up_read(&mm->mmap_sem);
	mmput(mm);
}

void do_page_fault_ret_pre_code (void)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma = 0;
	inst_us_proc_t *task_inst_info = NULL;
	/*
	 * Because process threads have same address space
	 * we instrument only group_leader of all this threads
	 */
	struct task_struct *task = current->group_leader;

	unsigned long addr = 0, page = 0;


	// overhead
	struct timeval imi_tv1;
	struct timeval imi_tv2;
#define USEC_IN_SEC_NUM				1000000


//	struct proc_probes * pp = get_file_probes(&us_proc_info);
//	print_proc_probes(us_proc_info.pp);

	//if user-space instrumentation is not set
	if (!us_proc_info.path)
		return;

	if (task->flags & PF_KTHREAD) {
		DPRINTF("ignored kernel thread %d\n", task->pid);
		return;
	}

	addr = (unsigned long)swap_get_entry_data(&sa_dpf);
	page = addr & PAGE_MASK;
//	printk("### do_page_fault_ret_pre_code: addr=%x\n", addr);


	if (!strcmp(us_proc_info.path,"*"))
	{
		task_inst_info = get_task_inst_node(task);
		if (!task_inst_info)
		{
			task_inst_info = copy_task_inst_info(task,
							     &us_proc_info);
			put_task_inst_node(task, task_inst_info);
#ifdef __ANDROID
			if (is_java_inst_enabled()) {
				find_libdvm_for_task(task, task_inst_info);
			}
#endif /* __ANDROID */
		}

		// overhead
		printk("####### T_0\n");
		do_gettimeofday(&imi_tv1);
		install_page_probes(page, task, us_proc_info.pp, addr);
//		install_mapped_ips (task, task_inst_info, 1);
		do_gettimeofday(&imi_tv2);
		printk("####### T_1\n");
		imi_sum_hit++;
		imi_sum_time += ((imi_tv2.tv_sec - imi_tv1.tv_sec) *  USEC_IN_SEC_NUM +
			(imi_tv2.tv_usec - imi_tv1.tv_usec));
		return;
	}

	task_inst_info = &us_proc_info;
	//DPRINTF("do_page_fault from proc %d-%d-%d", current->pid, task_inst_info->tgid, task_inst_info->unres_ips_count);
	if (!is_java_inst_enabled()
	    && (task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count
		+ task_inst_info->unres_otg_ips_count) == 0)
	{
		//DPRINTF("do_page_fault: there no unresolved IPs");
		return;
	}

	if (task_inst_info->tgid == 0)
	{
		mm = task->active_mm;
		if (mm)
		{
//			down_read (&mm->mmap_sem);
			vma = mm->mmap;
			while (vma)
			{
				if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
				{
					if (vma->vm_file->f_dentry == task_inst_info->m_f_dentry)
					{
						break;
					}
#ifdef SLP_APP
					if (is_slp_app_with_dentry(vma, task_inst_info->m_f_dentry)) {
						break;
					}
#endif /* SLP_APP */
#ifdef ANDROID_APP
					if (is_android_app_with_dentry(vma, task_inst_info->m_f_dentry)) {
						break;
					}
#endif /* ANDROID_APP */
				}
				vma = vma->vm_next;
			}
//			up_read (&mm->mmap_sem);
//			mmput (mm);
		} else {
			//			DPRINTF ("proc %s/%d has no mm", current->comm, current->pid);
		}
		if (vma)
		{
		     DPRINTF ("do_page_fault found target proc %s(%d)", task->comm, task->pid);
		     task_inst_info->tgid = task->pid;
		     gl_nNotifyTgid = task->tgid;
		}
	}
	if (task_inst_info->tgid == task->tgid)
	{
		//DPRINTF("do_page_fault from target proc %d", task_inst_info->tgid);
#ifdef __ANDROID
		if (is_java_inst_enabled()) {
			find_libdvm_for_task(task, &us_proc_info);
		}
#endif /* __ANDROID */

		do_gettimeofday(&imi_tv1);
		install_page_probes(page, task, us_proc_info.pp, addr);
//		install_mapped_ips (task, &us_proc_info, 1);
		do_gettimeofday(&imi_tv2);
		imi_sum_hit++;
		imi_sum_time += ((imi_tv2.tv_sec - imi_tv1.tv_sec) *  USEC_IN_SEC_NUM +
			(imi_tv2.tv_usec - imi_tv1.tv_usec));
	}
	//DPRINTF("do_page_fault from proc %d-%d exit", task->pid, task_inst_info->pid);
}

EXPORT_SYMBOL_GPL(do_page_fault_ret_pre_code);


void do_exit_probe_pre_code (void)
{
	// TODO: remove task
}
EXPORT_SYMBOL_GPL(do_exit_probe_pre_code);

void mm_release_probe_pre_code(void)
{
	int iRet, del = 0;
	struct task_struct *task;
	inst_us_proc_t *task_inst_info = NULL;

	//if user-space instrumentation is not set
	if (!us_proc_info.path || current->tgid != current->pid)
		return;

	if (!strcmp(us_proc_info.path,"*"))
	{
		task_inst_info = get_task_inst_node(current);
		if (task_inst_info)
		{
			iRet = uninstall_mapped_ips (current, task_inst_info, 1);
			if (iRet != 0)
				EPRINTF ("failed to uninstall IPs (%d)!", iRet);
			dbi_unregister_all_uprobes(current, 1);
		}
	}
	else
	{
		if (current->tgid != us_proc_info.tgid)
			return;
			del = 1;
		// look for another process with the same tgid
		rcu_read_lock ();
		for_each_process (task)
		{
			if ((task->pid != current->pid) && (task->tgid == us_proc_info.tgid))
			{
				del = 0;
				break;
			}
		}
		rcu_read_unlock ();
		if (del)
		{
			int i;
			iRet = uninstall_mapped_ips (current, &us_proc_info, 1);
			if (iRet != 0)
				EPRINTF ("failed to uninstall IPs (%d)!", iRet);
			dbi_unregister_all_uprobes(current, 1);
			us_proc_info.tgid = 0;
			for(i = 0; i < us_proc_info.libs_count; i++)
				us_proc_info.p_libs[i].loaded = 0;
		}
	}
}
EXPORT_SYMBOL_GPL(mm_release_probe_pre_code);


static void recover_child(struct task_struct *child_task, inst_us_proc_t *parent_iup)
{
	int i, k;
	for(i = 0; i < parent_iup->libs_count; ++i)
	{
		for(k = 0; k < parent_iup->p_libs[i].ips_count; ++k)
			if(parent_iup->p_libs[i].p_ips[k].installed)
				arch_disarm_uprobe(&parent_iup->p_libs[i].p_ips[k].jprobe.kp, child_task);

		for(k = 0; k < parent_iup->p_libs[i].vtps_count; ++k)
			if(parent_iup->p_libs[i].p_vtps[k].installed)
				arch_disarm_uprobe(&parent_iup->p_libs[i].p_vtps[k].jprobe.kp, child_task);
	}
}

static void rm_uprobes_child(struct task_struct *new_task)
{
	if(!strcmp(us_proc_info.path, "*")) {
		inst_us_proc_t *task_inst_info = get_task_inst_node(current);
		if(task_inst_info)
			recover_child(new_task, task_inst_info);
	} else {
		if(us_proc_info.tgid == current->tgid) {
			recover_child(new_task, &us_proc_info);
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

	if (!strcmp(us_proc_info.path, "*")) {
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

int uretprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, us_proc_ip_t * ip)
{
	int retval = regs_return_value(regs);
	unsigned long addr = (unsigned long)ip->jprobe.kp.addr;

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

static int register_usprobe (struct task_struct *task, struct mm_struct *mm, us_proc_ip_t * ip, int atomic, kprobe_opcode_t * islot)
{
	int ret = 0;
	ip->jprobe.kp.tgid = task->tgid;
	//ip->jprobe.kp.addr = (kprobe_opcode_t *) addr;

//	printk("### register_usprobe: offset=%x, j_addr=%x, ret_addr=%x\n",
//			ip->offset, ip->jprobe.kp.addr, ip->retprobe.kp.addr);

//	return 0;

	if(!ip->jprobe.entry) {
		if (dbi_ujprobe_event_handler_custom_p != NULL)
		{
			ip->jprobe.entry = (kprobe_opcode_t *) dbi_ujprobe_event_handler_custom_p;
			DPRINTF("Set custom event handler for %x\n", ip->offset);
		}
		else
		{
			ip->jprobe.entry = (kprobe_opcode_t *) ujprobe_event_handler;
			DPRINTF("Set default event handler for %x\n", ip->offset);
		}
	}
	if(!ip->jprobe.pre_entry) {
		if (dbi_ujprobe_event_pre_handler_custom_p != NULL)
		{
			ip->jprobe.pre_entry = (kprobe_pre_entry_handler_t) dbi_ujprobe_event_pre_handler_custom_p;
			DPRINTF("Set custom pre handler for %x\n", ip->offset);
		}
		else
		{
			ip->jprobe.pre_entry = (kprobe_pre_entry_handler_t) ujprobe_event_pre_handler;
			DPRINTF("Set default pre handler for %x\n", ip->offset);
		}
	}
	ip->jprobe.priv_arg = ip;
	ret = dbi_register_ujprobe (task, mm, &ip->jprobe, atomic);
	if (ret)
	{
		DPRINTF ("dbi_register_ujprobe() failure %d", ret);
		return ret;
	}

	// Mr_Nobody: comment for valencia
	ip->retprobe.kp.tgid = task->tgid;
	//ip->retprobe.kp.addr = (kprobe_opcode_t *) addr;
	if(!ip->retprobe.handler) {
	 	if (dbi_uretprobe_event_handler_custom_p != NULL)
	 		ip->retprobe.handler = (kretprobe_handler_t) dbi_uretprobe_event_handler_custom_p;
	 	else {
	 		ip->retprobe.handler = (kretprobe_handler_t) uretprobe_event_handler;
			//DPRINTF("Failed custom dbi_uretprobe_event_handler_custom_p");
		}
	}
	ip->retprobe.priv_arg = ip;
	ret = dbi_register_uretprobe (task, mm, &ip->retprobe, atomic);
	if (ret)
	{
		EPRINTF ("dbi_register_uretprobe() failure %d", ret);
		return ret;
	}
	return 0;
}

static int unregister_usprobe (struct task_struct *task, us_proc_ip_t * ip, int atomic)
{
	dbi_unregister_ujprobe (task, &ip->jprobe, atomic);
	dbi_unregister_uretprobe (task, &ip->retprobe, atomic);
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

/*function call removes all OTG-probes installed in library "lib_to_delete"*/
void otg_probe_list_clean(char* lib_to_delete)
{
	struct task_struct *task = current->group_leader;
	struct mm_struct *mm;
	struct vm_area_struct *vma = 0;
	char *filename = "";
	char *buf = "";
	unsigned long int addr_max = 0;
	unsigned long int addr_min = 0;
	int err;
	us_proc_otg_ip_t *p;

	mm = task->active_mm;
/*find in process space map file with name "lib_to_delete" and flag VM_EXEC
and save address borders of this file*/
	if (mm) {
		vma = mm->mmap;
		while (vma) {
			if(vma->vm_file) {
				if(vma->vm_file->f_dentry) {
					filename = d_path(&vma->vm_file->f_path, buf, 256);
					if((strcmp(lib_to_delete, filename) == 0) && (vma->vm_flags & VM_EXEC)) {
						addr_min = vma->vm_start;
						addr_max = vma->vm_end;
						break;
					}
				}
			}
			vma = vma->vm_next;
		}
	}
/*remove OTG-probe if its address is between addr_min and addr_max*/
	list_for_each_entry_rcu (p, &otg_us_proc_info, list) {
		if (!p->ip.installed) {
			continue;
		}
		if ( ((unsigned long)p->ip.jprobe.kp.addr <  addr_max) &&
		     ((unsigned long)p->ip.jprobe.kp.addr >= addr_min) ) {
			err = unregister_usprobe(task, &p->ip, 1);
			if (err != 0) {
				EPRINTF("failed to uninstall IP at %p. Error %d!",
					 p->ip.jprobe.kp.addr, err);
				continue;
			}
			p->ip.installed = 0;
		}
	}
}
EXPORT_SYMBOL_GPL(otg_probe_list_clean);
