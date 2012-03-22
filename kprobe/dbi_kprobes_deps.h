#ifndef _DBI_KPROBES_DEPS_H
#define _DBI_KPROBES_DEPS_H

/*
 *  Dynamic Binary Instrumentation Module based on KProbes
 *  modules/kprobe/dbi_kprobes_deps.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Samsung Electronics, 2006-2010
 *
 * 2008-2009    Alexey Gerenkov <a.gerenkov@samsung.com> User-Space
 *              Probes initial implementation; Support x86/ARM/MIPS for both user and kernel spaces.
 * 2010         Ekaterina Gorelkina <e.gorelkina@samsung.com>: redesign module for separating core and arch parts 
 *

 */

#include <linux/version.h>	// LINUX_VERSION_CODE, KERNEL_VERSION()
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 12))
#define synchronize_sched	synchronize_kernel
#endif

//--------------------- Declaration of module dependencies ------------------------//

#define DECLARE_MOD_FUNC_DEP(name, ret, ...) ret(*__ref_##name)(__VA_ARGS__)
#define DECLARE_MOD_CB_DEP(name, ret, ...) ret(*name)(__VA_ARGS__)


//----------------- Implementation of module dependencies wrappers -----------------//

#define DECLARE_MOD_DEP_WRAPPER(name, ret, ...) ret name(__VA_ARGS__)
#define IMP_MOD_DEP_WRAPPER(name, ...) \
{ \
	return __ref_##name(__VA_ARGS__); \
}


//---------------------- Module dependencies initialization --------------------//

#define INIT_MOD_DEP_VAR(dep, name) \
{ \
	__ref_##dep = (void *) kallsyms_search (#name); \
	if (!__ref_##dep) \
	{ \
		DBPRINTF (#name " is not found! Oops. Where is it?"); \
		return -ESRCH; \
	} \
}

#define INIT_MOD_DEP_CB(dep, name) \
{ \
	dep = (void *) kallsyms_search (#name); \
	if (!dep) \
	{ \
		DBPRINTF (#name " is not found! Oops. Where is it?"); \
		return -ESRCH; \
	} \
}


int init_module_dependencies(void);

int access_process_vm_atomic(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
int get_user_pages_uprobe(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, int len, int write, int force,
		struct page **pages, struct vm_area_struct **vmas);

#define read_proc_vm_atomic(tsk, addr, buf, len)	access_process_vm_atomic (tsk, addr, buf, len, 0)
#define write_proc_vm_atomic(tsk, addr, buf, len)	access_process_vm_atomic (tsk, addr, buf, len, 1)
int page_present (struct mm_struct *mm, unsigned long addr);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38)
#define get_user_pages_atomic 	get_user_pages
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */
#define get_user_pages_atomic  get_user_pages_uprobe
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 38) */



#endif /* _DBI_KPROBES_DEPS_H */
