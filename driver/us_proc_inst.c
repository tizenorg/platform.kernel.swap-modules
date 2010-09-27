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

static int register_usprobe (struct task_struct *task, struct mm_struct *mm, us_proc_ip_t * ip, int atomic, kprobe_opcode_t * islot);
static int unregister_usprobe (struct task_struct *task, us_proc_ip_t * ip, int atomic);

int us_proc_probes;

struct task_inst_info_node {
	struct list_head      plist;
	inst_us_proc_t *      task_inst_info;
	int                   tgid;
};
LIST_HEAD(task_inst_info_list);

/**
 * Prepare copy of instrumentation data for task 
 * in case of library only instrumentation 
 */

inst_us_proc_t* copy_task_inst_info (inst_us_proc_t * task_inst_info)
{
	int i, j, len;

	inst_us_proc_t* copy_task_inst_info = 0;

	int unres_ips_count = 0, unres_vtps_count = 0;

	copy_task_inst_info = kmalloc (sizeof (inst_us_proc_t), GFP_KERNEL);
	memset ((void *) copy_task_inst_info, 0, sizeof (inst_us_proc_t));

	copy_task_inst_info->path = task_inst_info->path;
	copy_task_inst_info->m_f_dentry = NULL;

	copy_task_inst_info->libs_count = task_inst_info->libs_count;
	copy_task_inst_info->p_libs = 
		kmalloc (task_inst_info->libs_count * sizeof (us_proc_lib_t), GFP_KERNEL);

	if (!copy_task_inst_info->p_libs)
	{
		DPRINTF ("No enough memory for copy_task_inst_info->p_libs");
		return -ENOMEM;
	}
	memcpy (copy_task_inst_info->p_libs, task_inst_info->p_libs, 
			copy_task_inst_info->libs_count * sizeof (us_proc_lib_t));

	for (i = 0; i < copy_task_inst_info->libs_count; i++)
	{
		if (copy_task_inst_info->p_libs[i].ips_count > 0) 
		{
			unres_ips_count += copy_task_inst_info->p_libs[i].ips_count;

			copy_task_inst_info->p_libs[i].p_ips = 
				kmalloc (copy_task_inst_info->p_libs[i].ips_count * sizeof (us_proc_ip_t), GFP_KERNEL);

			if (!copy_task_inst_info->p_libs[i].p_ips)
			{
				DPRINTF ("No enough memory for copy_task_inst_info->p_libs[i].p_ips");
				return -ENOMEM;
			}

			memcpy (copy_task_inst_info->p_libs[i].p_ips, task_inst_info->p_libs[i].p_ips, 
					copy_task_inst_info->p_libs[i].ips_count * sizeof (us_proc_ip_t));
			for (j = 0; j < copy_task_inst_info->p_libs[i].ips_count; j++)
			{
				copy_task_inst_info->p_libs[i].p_ips[j].installed = 0;
				memset (&copy_task_inst_info->p_libs[i].p_ips[j].jprobe, 0, sizeof(struct jprobe));
				memset(&copy_task_inst_info->p_libs[i].p_ips[j].retprobe, 0, sizeof(struct kretprobe));
			}

			unres_ips_count += copy_task_inst_info->p_libs[i].ips_count;
		}

		if (copy_task_inst_info->p_libs[i].vtps_count > 0) 
		{
			unres_vtps_count += copy_task_inst_info->p_libs[i].vtps_count;

			copy_task_inst_info->p_libs[i].p_vtps = 
				kmalloc (copy_task_inst_info->p_libs[i].vtps_count * sizeof (us_proc_vtp_t), GFP_KERNEL);

			if (!copy_task_inst_info->p_libs[i].p_vtps)
			{
				DPRINTF ("No enough memory for copy_task_inst_info->p_libs[i].p_vtps");
				return -ENOMEM;
			}

			memcpy (copy_task_inst_info->p_libs[i].p_vtps, task_inst_info->p_libs[i].p_vtps, 
					copy_task_inst_info->p_libs[i].vtps_count * sizeof (us_proc_vtp_t));
			for (j = 0; j < copy_task_inst_info->p_libs[i].vtps_count; j++)
			{
				copy_task_inst_info->p_libs[i].p_vtps[j].installed = 0;
				memset (&copy_task_inst_info->p_libs[i].p_vtps[j].jprobe, 0, sizeof(struct jprobe));
			}
			unres_vtps_count = copy_task_inst_info->p_libs[i].vtps_count;
		}

		copy_task_inst_info->p_libs[i].m_f_dentry = task_inst_info->p_libs[i].m_f_dentry;
		copy_task_inst_info->p_libs[i].loaded = 0;
	}
	copy_task_inst_info->unres_ips_count = unres_ips_count;
	copy_task_inst_info->unres_vtps_count = unres_vtps_count;

	return copy_task_inst_info;
}

inst_us_proc_t* get_task_inst_node(struct task_struct *task)
{
	struct task_inst_info_node *node, *tnode;

	DPRINTF ("Before list_for_each_entry_safe");
	list_for_each_entry_safe(node, tnode, &task_inst_info_list, plist) 
	{
		if (node && task && node->tgid == task->tgid) 
		{
			DPRINTF ("Before return node->task_inst_info tgid = %i\n", task->tgid);
			return node->task_inst_info;
		}
	}
	return NULL;
}

void put_task_inst_node(struct task_struct *task, inst_us_proc_t *task_inst_info)
{
	struct task_inst_info_node * node;

	node = kmalloc (sizeof(struct task_inst_info_node), GFP_KERNEL);

	node->tgid = task->tgid;
	node->task_inst_info = task_inst_info;

	list_add_tail (&(node->plist), &task_inst_info_list);
}


void clear_task_inst_info()
{
	struct list_head *node, *tmp;

	list_for_each_safe(node, tmp, &task_inst_info_list)
		list_del(node);
}

static int find_task_by_path (const char *path, struct task_struct **p_task, struct list_head *tids)
{
	int found = 0;
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct nameidata nd;

	*p_task = 0;

	/* find corresponding dir entry, this is also check for valid path */
	// TODO: test - try to instrument process with non-existing path
	// TODO: test - try to instrument process  with existing path and delete file just after start
	if (path_lookup (path, LOOKUP_FOLLOW, &nd) != 0)
	{
		EPRINTF ("failed to lookup dentry for path %s!", path);
		return -EINVAL;
	}

	rcu_read_lock ();
	for_each_process (task)	{
		mm = get_task_mm (task);
		if (!mm)
			continue;
		down_read (&mm->mmap_sem);
		vma = mm->mmap;
		while (vma) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
				if (vma->vm_file->f_dentry == nd.dentry) {
#else
					if (vma->vm_file->f_dentry == nd.path.dentry) {
#endif
						if (!*p_task) {
							*p_task = task;
							get_task_struct (task);
						}
						//break;
					}
				}
				vma = vma->vm_next;
			}
			up_read (&mm->mmap_sem);
			mmput (mm);
			if (found)
				break;
		}
		rcu_read_unlock ();

		if (*p_task)
		{
			DPRINTF ("found pid %d for %s.", (*p_task)->pid, path);
			gl_nNotifyTgid = current->tgid;
		}
		else
		{
			DPRINTF ("pid for %s not found!", path);
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
		path_release (&nd);
#else
		path_put (&nd.path);
#endif
		return 0;
}

#if defined(CONFIG_MIPS)
#	define ARCH_REG_VAL(regs, idx)	regs->regs[idx]
#elif defined(CONFIG_ARM)
#	define ARCH_REG_VAL(regs, idx)	regs->uregs[idx]
#else
#	define ARCH_REG_VAL(regs, idx)	0
#	warning ARCH_REG_VAL is not implemented for this architecture. FBI will work improperly or even crash!!!
#endif // ARCH
	
DEFINE_PER_CPU (us_proc_vtp_t *, gpVtp) = NULL;
DEFINE_PER_CPU (struct pt_regs *, gpCurVtpRegs) = NULL;

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

	list_for_each_entry_rcu (vtp_data, &vtp->list, list)
	{
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
				if (current->active_mm)
				{
					struct page *page;
					struct vm_area_struct *vma;
					void *maddr;
					int len;
					if (get_user_pages_atomic (current, current->active_mm, vaddr, 1, 0, 1, &page, &vma) <= 0)
					  {
						EPRINTF ("get_user_pages_atomic failed for proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
						break;
					  }
					maddr = kmap_atomic (page, KM_USER0);
					len = strlen (maddr + (vaddr & ~PAGE_MASK));
					sval = kmalloc (len + 1, GFP_KERNEL);
					if (!sval)
						EPRINTF ("failed to alloc memory for string in proc %s/%u addr %lu!", current->comm, current->pid, vaddr);
					else
					{
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
	uprobe_return ();
}

static int install_mapped_ips (struct task_struct *task, inst_us_proc_t* task_inst_info, int atomic)
{
	struct vm_area_struct *vma;
	int i, k, err, retry;
	unsigned long addr;
	unsigned int old_ips_count, old_vtps_count;
	struct mm_struct *mm;
	struct ip_node {
		struct list_head	plist;
		us_proc_ip_t *		ip;
	} * nip, *tnip;
	LIST_HEAD(iplist);
	struct vtp_node {
		struct list_head	plist;
		us_proc_vtp_t *		vtp;		
	} * nvtp, *tnvtp;
	LIST_HEAD(vtplist);
		DPRINTF ("mapped_ips 1\n");
_restart:
	mm = atomic ? task->active_mm : get_task_mm (task);
	if (!mm){
		//		DPRINTF ("proc %d has no mm", task->pid);
		return task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count;
	}
	old_ips_count = task_inst_info->unres_ips_count;
	old_vtps_count = task_inst_info->unres_vtps_count;
	if(!atomic) 
		down_read (&mm->mmap_sem);
	vma = mm->mmap;
	while (vma)
	{
		// skip non-text section
		if (!(vma->vm_flags & VM_EXEC) || !vma->vm_file || (vma->vm_flags & VM_ACCOUNT) || 
				!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE)) || 
				!(vma->vm_flags & (VM_READ | VM_MAYREAD)))
		{
			vma = vma->vm_next;
			continue;
		}
		for (i = 0; i < task_inst_info->libs_count; i++)
		{	
			//TODO: test - try to instrument non-existing libs
			if (vma->vm_file->f_dentry == task_inst_info->p_libs[i].m_f_dentry)
			{
				DPRINTF ("	if (vma->vm_file->f_dentry == task_inst_info->p_libs[i].m_f_dentry)\n");
				for (k = 0; k < task_inst_info->p_libs[i].ips_count; k++/*, slot_idx++*/)
				{
					if (!task_inst_info->p_libs[i].p_ips[k].installed)
					{
						addr = task_inst_info->p_libs[i].p_ips[k].offset;
						if (!(vma->vm_flags & VM_EXECUTABLE))
							addr += vma->vm_start;
						if (page_present (mm, addr))
						  {
						    if (!task_inst_info->p_libs[i].p_ips[k].installed)
							{
								task_inst_info->unres_ips_count--;
								task_inst_info->p_libs[i].p_ips[k].installed = 1;
								DPRINTF ("pid %d, %s sym is loaded at %lx/%lx.", task->pid, task_inst_info->p_libs[i].path, task_inst_info->p_libs[i].p_ips[k].offset, addr);
								nip = kmalloc(sizeof(struct ip_node), GFP_KERNEL);
								if(!nip){
									EPRINTF ("failed to allocate list item for IP!");
									continue;
								}
								task_inst_info->p_libs[i].p_ips[k].jprobe.kp.addr = (kprobe_opcode_t *) addr;
								task_inst_info->p_libs[i].p_ips[k].retprobe.kp.addr = (kprobe_opcode_t *) addr;
								INIT_LIST_HEAD (&nip->plist);
								nip->ip = &task_inst_info->p_libs[i].p_ips[k];
								list_add_tail (&nip->plist, &iplist);
							}
						}
					}
				}
				for (k = 0; k < task_inst_info->p_libs[i].vtps_count; k++)
				{
					if (!task_inst_info->p_libs[i].p_vtps[k].installed)
					{
						addr = task_inst_info->p_libs[i].p_vtps[k].addr;
						if (!(vma->vm_flags & VM_EXECUTABLE))
							addr += vma->vm_start;
							if (page_present (mm, addr))
							  {
							        task_inst_info->unres_vtps_count--;
							        task_inst_info->p_libs[i].p_vtps[k].installed = 1;
								task_inst_info->p_libs[i].p_vtps[k].jprobe.kp.tgid = task_inst_info->tgid;
								task_inst_info->p_libs[i].p_vtps[k].jprobe.kp.addr = (kprobe_opcode_t *) addr;
								task_inst_info->p_libs[i].p_vtps[k].jprobe.entry = (kprobe_opcode_t *) us_vtp_event_handler;
								task_inst_info->p_libs[i].p_vtps[k].jprobe.pre_entry = (kprobe_pre_entry_handler_t) us_vtp_event_pre_handler;
								task_inst_info->p_libs[i].p_vtps[k].jprobe.priv_arg = &task_inst_info->p_libs[i].p_vtps[k];
								nvtp = kmalloc(sizeof(struct vtp_node), GFP_KERNEL);
								if(!nvtp){
									EPRINTF ("failed to allocate list item for VTP!");
									continue;
								}
								INIT_LIST_HEAD (&nvtp->plist);
								nvtp->vtp = &task_inst_info->p_libs[i].p_vtps[k];
								list_add_tail (&nvtp->plist, &vtplist);
							  }
					}
				}
				if(!(vma->vm_flags & VM_EXECUTABLE) && !task_inst_info->p_libs[i].loaded){
					char *p;
					DPRINTF ("post dyn lib event %s/%s", current->comm, task_inst_info->p_libs[i].path);
					// if we installed something, post library info for those IPs
					p = strrchr(task_inst_info->p_libs[i].path, '/');
					if(!p)
						p = task_inst_info->p_libs[i].path;
					else
						p++;
					task_inst_info->p_libs[i].loaded = 1;
					pack_event_info (DYN_LIB_PROBE_ID, RECORD_ENTRY, "spd", 
							p, vma->vm_start, vma->vm_end-vma->vm_start);
				}
			}
		}
		vma = vma->vm_next;
	}
	if(!atomic){	
		up_read (&mm->mmap_sem);
		mmput (mm);
	}
	if(!list_empty(&iplist) || !list_empty(&vtplist))
	  {
		DPRINTF ("Unres IPs/VTPs %d/%d -> %d/%d.", old_ips_count, old_vtps_count, task_inst_info->unres_ips_count, task_inst_info->unres_vtps_count);
	  }
		
	retry = 0;
	list_for_each_entry_safe(nip, tnip, &iplist, plist) 
	  {
		DPRINTF ("Install %p/%d IP at %lx.", task, task->pid, nip->ip->offset);
		if((PAGE_SIZE-(nip->ip->offset % PAGE_SIZE)) < MAX_INSN_SIZE)
		  {
			retry = 1;
			DPRINTF ("Possibly 1st insn of IP at %lx lies on 2 pages.",  nip->ip->offset);
		  }
		err = register_usprobe (task, mm, nip->ip, atomic, 0);
		if (err != 0)
			EPRINTF ("failed to install IP at %lx/%p. Error %d!", nip->ip->offset, nip->ip->jprobe.kp.addr, err);
		list_del(&nip->plist);
		kfree(nip);
	  }
	list_for_each_entry_safe(nvtp, tnvtp, &vtplist, plist) 
	  {
		DPRINTF ("Install VTP at %p.", nvtp->vtp->jprobe.kp.addr);
		if((PAGE_SIZE-(nvtp->vtp->addr % PAGE_SIZE)) < MAX_INSN_SIZE){
			retry = 1;
			DPRINTF ("Possibly 1st insn of VTP %lx lies on 2 pages.", nvtp->vtp->addr);
		}
		err = register_ujprobe (task, mm, &nvtp->vtp->jprobe, atomic);
		if (err)
			EPRINTF ("failed to install VTP at %p. Error %d!", nvtp->vtp->jprobe.kp.addr, err);
		list_del(&nvtp->plist);
		kfree(nvtp);
	  }

	if(retry) goto _restart;

	return task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count;
}

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
				unregister_ujprobe (task, &task_inst_info->p_libs[i].p_vtps[k].jprobe, atomic);
				task_inst_info->unres_vtps_count++;
				task_inst_info->p_libs[i].p_vtps[k].installed = 0;
			}
		}
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
			unregister_all_uprobes(t, 1);
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

	iRet = uninstall_kernel_probe (pf_addr, US_PROC_PF_INSTLD,
			0, &pf_probe);
	if (iRet)
		EPRINTF ("uninstall_kernel_probe(do_page_fault) result=%d!", iRet);

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
				unregister_all_uprobes(task, 1);
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
			unregister_all_uprobes(task, 1);
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

	if (pprobe)
		*pprobe = probe;

	return 0;
}

int inst_usr_space_proc (void)
{
	int ret, i;
	struct task_struct *task = 0;
	inst_us_proc_t *task_inst_info = NULL;

	if (!us_proc_info.path)
		return 0;

	for (i = 0; i < us_proc_info.libs_count; i++)
		us_proc_info.p_libs[i].loaded = 0;
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
		for_each_process (task)
		{
			if (task)
			{
				task_inst_info = get_task_inst_node(task);
				if (!task_inst_info) 
				{
					task_inst_info = copy_task_inst_info (&us_proc_info);
					put_task_inst_node(task, task_inst_info);
				}
				install_mapped_ips (task, task_inst_info, 1);
				//put_task_struct (task);
				task_inst_info = NULL;
			}
		}
	} 
	else
	{
		ret = find_task_by_path (us_proc_info.path, &task, NULL);

		if (task)
		{
			us_proc_info.tgid = task->pid;
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
	// enable 'do_exit' probe to detect when user proc exits in order to remove user space probes
	ret = install_kernel_probe (exit_addr, US_PROC_EXIT_INSTLD, 0, &exit_probe);
	if (ret != 0)
	{
		EPRINTF ("install_kernel_probe(do_exit) result=%d!", ret);
		return ret;
	}

	return 0;
}

char expath[512];

void do_page_fault_ret_pre_code (void)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma = 0;
	inst_us_proc_t *task_inst_info = NULL;

	if (!us_proc_info.path)
		return;

	if (!strcmp(us_proc_info.path,"*"))
	{
		task_inst_info = get_task_inst_node(current);
		if (!task_inst_info) 
		{
			task_inst_info = copy_task_inst_info (&us_proc_info);
			put_task_inst_node(current, task_inst_info);
		}
		install_mapped_ips (current, task_inst_info, 1);
		return;
	}

	task_inst_info = &us_proc_info;
	//DPRINTF("do_page_fault from proc %d-%d-%d", current->pid, task_inst_info->tgid, task_inst_info->unres_ips_count);
	if ((task_inst_info->unres_ips_count + task_inst_info->unres_vtps_count) == 0)
	{
		//DPRINTF("do_page_fault: there no unresolved IPs");
		return;
	}

	if (task_inst_info->tgid == 0)
	{
		mm = get_task_mm (current);//current->active_mm;
		if (mm)
		{
			down_read (&mm->mmap_sem);
			vma = mm->mmap;
			while (vma)
			{
				if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
				{
					if (vma->vm_file->f_dentry == task_inst_info->m_f_dentry)
					{
						break;
					}
				}
				vma = vma->vm_next;
			}
			up_read (&mm->mmap_sem);
			mmput (mm);
		} else {
			//			DPRINTF ("proc %s/%d has no mm", current->comm, current->pid);
		}
		if (vma)
		{
			DPRINTF ("do_page_fault found target proc %s(%d)", current->comm, current->pid);
			task_inst_info->tgid = current->pid;
			gl_nNotifyTgid = current->tgid;
		}
	}
	if (task_inst_info->tgid == current->tgid)
	{
		//DPRINTF("do_page_fault from target proc %d", task_inst_info->tgid);
		install_mapped_ips (current, &us_proc_info, 1);
	}
		//DPRINTF("do_page_fault from proc %d-%d exit", current->pid, task_inst_info->pid);
}

EXPORT_SYMBOL_GPL(do_page_fault_ret_pre_code);

void do_exit_probe_pre_code (void)
{
	int iRet, del = 0;
	struct task_struct *task;
	inst_us_proc_t *task_inst_info = NULL;


	if (!strcmp(us_proc_info.path,"*"))
	{
		task_inst_info = get_task_inst_node(current);
		if (task_inst_info) 
		{
			iRet = uninstall_mapped_ips (current, task_inst_info, 1);
			if (iRet != 0)
				EPRINTF ("failed to uninstall IPs (%d)!", iRet);
			unregister_all_uprobes(current, 1);
		}
		return;
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
			unregister_all_uprobes(current, 1);
			us_proc_info.tgid = 0;
			for(i = 0; i < us_proc_info.libs_count; i++)
				us_proc_info.p_libs[i].loaded = 0;
		}
	}
}
EXPORT_SYMBOL_GPL(do_exit_probe_pre_code);

DEFINE_PER_CPU (us_proc_ip_t *, gpCurIp) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpCurIp);
DEFINE_PER_CPU(struct pt_regs *, gpUserRegs) = NULL;
EXPORT_PER_CPU_SYMBOL_GPL(gpUserRegs);

// XXX MCPP: introduced custom default handlers defined in (exported from) another kernel module(s)
unsigned long (* ujprobe_event_pre_handler_custom_p)(us_proc_ip_t *, struct pt_regs *) = NULL;
EXPORT_SYMBOL(ujprobe_event_pre_handler_custom_p);
void (* ujprobe_event_handler_custom_p)() = NULL;
EXPORT_SYMBOL(ujprobe_event_handler_custom_p);
int (* uretprobe_event_handler_custom_p)(struct kretprobe_instance *, struct pt_regs *, us_proc_ip_t *) = NULL;
EXPORT_SYMBOL(uretprobe_event_handler_custom_p);

unsigned long ujprobe_event_pre_handler (us_proc_ip_t * ip, struct pt_regs *regs)
{
	__get_cpu_var (gpCurIp) = ip;
	__get_cpu_var (gpUserRegs) = regs;
	return 0;
}

void ujprobe_event_handler (unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5, unsigned long arg6)
{
	us_proc_ip_t *ip = __get_cpu_var (gpCurIp);
	pack_event_info (US_PROBE_ID, RECORD_ENTRY, "ppppppp", ip->jprobe.kp.addr, arg1, arg2, arg3, arg4, arg5, arg6);
	uprobe_return ();
}

int uretprobe_event_handler (struct kretprobe_instance *probe, struct pt_regs *regs, us_proc_ip_t * ip)
{
	int retval = regs_return_value(regs);
	pack_event_info (US_PROBE_ID, RECORD_RET, "pd", ip->retprobe.kp.addr, retval);
	return 0;
}

static int register_usprobe (struct task_struct *task, struct mm_struct *mm, us_proc_ip_t * ip, int atomic, kprobe_opcode_t * islot)
{
	int ret = 0;
	ip->jprobe.kp.tgid = task->tgid;
	//ip->jprobe.kp.addr = (kprobe_opcode_t *) addr;
	if(!ip->jprobe.entry) {
		if (ujprobe_event_handler_custom_p != NULL)
		{
			ip->jprobe.entry = (kprobe_opcode_t *) ujprobe_event_handler_custom_p;
			DPRINTF("Set custom event handler for %x\n", ip->offset);
		}
		else 
		{
			ip->jprobe.entry = (kprobe_opcode_t *) ujprobe_event_handler;
			DPRINTF("Set default event handler for %x\n", ip->offset);
		}
	}
	if(!ip->jprobe.pre_entry) {
		if (ujprobe_event_pre_handler_custom_p != NULL)
		{
			ip->jprobe.pre_entry = (kprobe_pre_entry_handler_t) ujprobe_event_pre_handler_custom_p;
			DPRINTF("Set custom pre handler for %x\n", ip->offset);
		}
		else 
		{
			ip->jprobe.pre_entry = (kprobe_pre_entry_handler_t) ujprobe_event_pre_handler;
			DPRINTF("Set default pre handler for %x\n", ip->offset);
		}
	}
	ip->jprobe.priv_arg = ip;
	ret = register_ujprobe (task, mm, &ip->jprobe, atomic);
	if (ret)
	{
		EPRINTF ("register_ujprobe() failure %d", ret);
		return ret;
	}
	ip->retprobe.kp.tgid = task->tgid;
	//ip->retprobe.kp.addr = (kprobe_opcode_t *) addr;
	if(!ip->retprobe.handler) {
		if (uretprobe_event_handler_custom_p != NULL)
			ip->retprobe.handler = (kretprobe_handler_t) uretprobe_event_handler_custom_p;
		else {
			ip->retprobe.handler = (kretprobe_handler_t) uretprobe_event_handler;
			//DPRINTF("Failed custom uretprobe_event_handler_custom_p");
		}
	}
	ip->retprobe.priv_arg = ip;
	ret = register_uretprobe (task, mm, &ip->retprobe, atomic);
	if (ret)
	{
		EPRINTF ("register_uretprobe() failure %d", ret);
		return ret;
	}
	return 0;
}

static int unregister_usprobe (struct task_struct *task, us_proc_ip_t * ip, int atomic)
{
	unregister_ujprobe (task, &ip->jprobe, atomic);
	unregister_uretprobe (task, &ip->retprobe, atomic);
	return 0;
}
