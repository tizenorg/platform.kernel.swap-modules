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

#include <linux/module.h>
#include <linux/sched.h>

#include <asm/pgtable.h>

#include "dbi_kprobes_deps.h"
#include "dbi_kdebug.h"


unsigned int *sched_addr;
unsigned int *fork_addr;


#define GUP_FLAGS_WRITE                  0x1
#define GUP_FLAGS_WRITE                  0x1
#define GUP_FLAGS_FORCE                  0x2
#define GUP_FLAGS_IGNORE_VMA_PERMISSIONS 0x4
#define GUP_FLAGS_IGNORE_SIGKILL         0x8

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 29)
struct mm_struct* init_mm_ptr;
struct mm_struct init_mm;
#endif


DECLARE_MOD_CB_DEP(kallsyms_search, unsigned long, const char *name);

DECLARE_MOD_FUNC_DEP(access_process_vm, int, struct task_struct * tsk, unsigned long addr, void *buf, int len, int write);

DECLARE_MOD_FUNC_DEP(find_extend_vma, struct vm_area_struct *, struct mm_struct * mm, unsigned long addr);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 30)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
DECLARE_MOD_FUNC_DEP(handle_mm_fault, int, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, int write_access);
#endif
#else
DECLARE_MOD_FUNC_DEP(handle_mm_fault, int, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, unsigned int flags);
#endif /* LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 30) */

DECLARE_MOD_FUNC_DEP(get_gate_vma, struct vm_area_struct *, struct task_struct *tsk);
DECLARE_MOD_FUNC_DEP(in_gate_area_no_task, int, unsigned long addr);
DECLARE_MOD_FUNC_DEP(follow_page, \
		struct page *, struct vm_area_struct * vma, \
		unsigned long address, unsigned int foll_flags);
DECLARE_MOD_FUNC_DEP(__flush_anon_page, \
		void, struct vm_area_struct *vma, struct page *page, \
		unsigned long vmaddr);
DECLARE_MOD_FUNC_DEP(vm_normal_page, \
		struct page *, struct vm_area_struct *vma, \
		unsigned long addr, pte_t pte);

DECLARE_MOD_FUNC_DEP(flush_ptrace_access, \
		void, struct vm_area_struct *vma, struct page *page, \
		unsigned long uaddr, void *kaddr, unsigned long len, int write);


#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
DECLARE_MOD_FUNC_DEP(put_task_struct, \
		void, struct task_struct *tsk);
#else 
DECLARE_MOD_FUNC_DEP(put_task_struct, \
		void, struct rcu_head * rhp);
#endif

	DECLARE_MOD_DEP_WRAPPER(access_process_vm, int, struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
IMP_MOD_DEP_WRAPPER (access_process_vm, tsk, addr, buf, len, write)

	DECLARE_MOD_DEP_WRAPPER (find_extend_vma, struct vm_area_struct *, struct mm_struct * mm, unsigned long addr)
IMP_MOD_DEP_WRAPPER (find_extend_vma, mm, addr)

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 30)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	DECLARE_MOD_DEP_WRAPPER (handle_mm_fault, \
			int, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, int write_access)
IMP_MOD_DEP_WRAPPER (handle_mm_fault, mm, vma, address, write_access)
#endif
#else
	DECLARE_MOD_DEP_WRAPPER (handle_mm_fault, \
			int, struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, unsigned int flags)
IMP_MOD_DEP_WRAPPER (handle_mm_fault, mm, vma, address, flags)
#endif

	DECLARE_MOD_DEP_WRAPPER (get_gate_vma, \
			struct vm_area_struct *, struct task_struct *tsk)
IMP_MOD_DEP_WRAPPER (get_gate_vma, tsk)

	DECLARE_MOD_DEP_WRAPPER (in_gate_area_no_task, int, unsigned long addr)
IMP_MOD_DEP_WRAPPER (in_gate_area_no_task, addr)

	DECLARE_MOD_DEP_WRAPPER (follow_page, \
			struct page *, struct vm_area_struct * vma, \
			unsigned long address, unsigned int foll_flags)
IMP_MOD_DEP_WRAPPER (follow_page, vma, address, foll_flags)

	DECLARE_MOD_DEP_WRAPPER (__flush_anon_page, \
			void, struct vm_area_struct *vma, \
			struct page *page, unsigned long vmaddr)
IMP_MOD_DEP_WRAPPER (__flush_anon_page, vma, page, vmaddr)

	DECLARE_MOD_DEP_WRAPPER(vm_normal_page, \
			struct page *, struct vm_area_struct *vma, \
			unsigned long addr, pte_t pte)
IMP_MOD_DEP_WRAPPER (vm_normal_page, vma, addr, pte)

	DECLARE_MOD_DEP_WRAPPER (flush_ptrace_access, \
			void, struct vm_area_struct *vma, struct page *page, \
			unsigned long uaddr, void *kaddr, unsigned long len, int write)
IMP_MOD_DEP_WRAPPER (flush_ptrace_access, vma, page, uaddr, kaddr, len, write)

int init_module_dependencies()
{

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 29)
  	init_mm_ptr = (struct mm_struct*) kallsyms_search ("init_mm");
	memcmp(init_mm_ptr, &init_mm, sizeof(struct mm_struct));
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	INIT_MOD_DEP_VAR(handle_mm_fault, handle_mm_fault);
#endif

	INIT_MOD_DEP_VAR(flush_ptrace_access, flush_ptrace_access);
	INIT_MOD_DEP_VAR(find_extend_vma, find_extend_vma);
	INIT_MOD_DEP_VAR(get_gate_vma, get_gate_vma);
	INIT_MOD_DEP_VAR(in_gate_area_no_task, in_gate_area_no_task);
	INIT_MOD_DEP_VAR(follow_page, follow_page);
	INIT_MOD_DEP_VAR(__flush_anon_page, __flush_anon_page);
	INIT_MOD_DEP_VAR(vm_normal_page, vm_normal_page);
	INIT_MOD_DEP_VAR(access_process_vm, access_process_vm);

#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
# if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11))
	INIT_MOD_DEP_VAR(put_task_struct, put_task_struct);
# else
	INIT_MOD_DEP_VAR(put_task_struct, __put_task_struct);
# endif
#else /*2.6.16 */
	INIT_MOD_DEP_VAR(put_task_struct, __put_task_struct_cb);
#endif

	return 0;
}

#define GUP_FLAGS_WRITE                  0x1
#define GUP_FLAGS_FORCE                  0x2
#define GUP_FLAGS_IGNORE_VMA_PERMISSIONS 0x4
#define GUP_FLAGS_IGNORE_SIGKILL         0x8

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
static inline int use_zero_page(struct vm_area_struct *vma)
{
	/*
	 * We don't want to optimize FOLL_ANON for make_pages_present()
	 * when it tries to page in a VM_LOCKED region. As to VM_SHARED,
	 * we want to get the page from the page tables to make sure
	 * that we serialize and update with any other user of that
	 * mapping.
	 */
	if (vma->vm_flags & (VM_LOCKED | VM_SHARED))
		return 0;
	/*
	 * And if we have a fault routine, it's not an anonymous region.
	 */
	return !vma->vm_ops || !vma->vm_ops->fault;
}

int __get_user_pages_uprobe(struct task_struct *tsk, struct mm_struct *mm,
		     unsigned long start, int len, int flags,
		struct page **pages, struct vm_area_struct **vmas)
{
	int i;
	unsigned int vm_flags = 0;
	int write = !!(flags & GUP_FLAGS_WRITE);
	int force = !!(flags & GUP_FLAGS_FORCE);
	int ignore = !!(flags & GUP_FLAGS_IGNORE_VMA_PERMISSIONS);
	int ignore_sigkill = !!(flags & GUP_FLAGS_IGNORE_SIGKILL);

	if (len <= 0)
		return 0;
	/* 
	 * Require read or write permissions.
	 * If 'force' is set, we only require the "MAY" flags.
	 */
	vm_flags  = write ? (VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	vm_flags &= force ? (VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);
	i = 0;

	do {
		struct vm_area_struct *vma;
		unsigned int foll_flags;

		//vma = find_extend_vma(mm, start);
		vma = find_vma(mm, start);
		if (!vma && in_gate_area(tsk, start)) {
			unsigned long pg = start & PAGE_MASK;
			struct vm_area_struct *gate_vma = get_gate_vma(tsk);
			pgd_t *pgd;
			pud_t *pud;
			pmd_t *pmd;
			pte_t *pte;

			/* user gate pages are read-only */
			if (!ignore && write)
				return i ? : -EFAULT;
			if (pg > TASK_SIZE)
				pgd = pgd_offset_k(pg);
			else
				pgd = pgd_offset_gate(mm, pg);
			BUG_ON(pgd_none(*pgd));
			pud = pud_offset(pgd, pg);
			BUG_ON(pud_none(*pud));
			pmd = pmd_offset(pud, pg);
			if (pmd_none(*pmd))
				return i ? : -EFAULT;
			pte = pte_offset_map(pmd, pg);
			if (pte_none(*pte)) {
				pte_unmap(pte);
				return i ? : -EFAULT;
			}
			if (pages) {
				struct page *page = vm_normal_page(gate_vma, start, *pte);
				pages[i] = page;
				if (page)
					get_page(page);
			}
			pte_unmap(pte);
			if (vmas)
				vmas[i] = gate_vma;
			i++;
			start += PAGE_SIZE;
			len--;
			continue;
		}

		if (!vma ||
		    (vma->vm_flags & (VM_IO | VM_PFNMAP)) ||
		    (!ignore && !(vm_flags & vma->vm_flags)))
			return i ? : -EFAULT;

		if (is_vm_hugetlb_page(vma)) {
#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
		  	i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &len, i);
#else
			i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &len, i, write);
#endif
			continue;
		}

		foll_flags = FOLL_TOUCH;
		if (pages)
			foll_flags |= FOLL_GET;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,30)
		if (!write && use_zero_page(vma))
		  foll_flags |= FOLL_ANON;
#endif
#endif

		do {
			struct page *page;

#if 0
			/*
			 * If we have a pending SIGKILL, don't keep faulting
			 * pages and potentially allocating memory, unless
			 * current is handling munlock--e.g., on exit. In
			 * that case, we are not allocating memory.  Rather,
			 * we're only unlocking already resident/mapped pages.
			 */
			if (unlikely(!ignore_sigkill &&
					fatal_signal_pending(current)))
				return i ? i : -ERESTARTSYS;
#endif

			if (write)
				foll_flags |= FOLL_WRITE;

			
			//cond_resched();

			DBPRINTF ("pages = %p vma = %p\n", pages, vma);
			while (!(page = follow_page(vma, start, foll_flags))) {
				int ret;
				ret = handle_mm_fault(mm, vma, start,
						foll_flags & FOLL_WRITE);

#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
				if (ret & VM_FAULT_WRITE)
				  foll_flags &= ~FOLL_WRITE;
				
				switch (ret & ~VM_FAULT_WRITE) {
				case VM_FAULT_MINOR:
				  tsk->min_flt++;
				  break;
				case VM_FAULT_MAJOR:
				  tsk->maj_flt++;
				  break;
				case VM_FAULT_SIGBUS:
				  return i ? i : -EFAULT;
				case VM_FAULT_OOM:
				  return i ? i : -ENOMEM;
				default:
				  BUG();
				}
				
#else
				if (ret & VM_FAULT_ERROR) {
				  if (ret & VM_FAULT_OOM)
				    return i ? i : -ENOMEM;
				  else if (ret & VM_FAULT_SIGBUS)
				    return i ? i : -EFAULT;
				  BUG();
				}
				if (ret & VM_FAULT_MAJOR)
				  tsk->maj_flt++;
				else
				  tsk->min_flt++;
				
				/*
				 * The VM_FAULT_WRITE bit tells us that
				 * do_wp_page has broken COW when necessary,
				 * even if maybe_mkwrite decided not to set
				 * pte_write. We can thus safely do subsequent
				 * page lookups as if they were reads. But only
				 * do so when looping for pte_write is futile:
				 * in some cases userspace may also be wanting
				 * to write to the gotten user page, which a
				 * read fault here might prevent (a readonly
				 * page might get reCOWed by userspace write).
				 */
				if ((ret & VM_FAULT_WRITE) &&
				    !(vma->vm_flags & VM_WRITE))
				  foll_flags &= ~FOLL_WRITE;
				
				//cond_resched();
#endif
				
			}

			if (IS_ERR(page))
				return i ? i : PTR_ERR(page);
			if (pages) {
				pages[i] = page;

#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
				flush_anon_page(page, start);
#else
				flush_anon_page(vma, page, start);
#endif
				flush_dcache_page(page);
			}
			if (vmas)
				vmas[i] = vma;
			i++;
			start += PAGE_SIZE;
			len--;
		} while (len && start < vma->vm_end);
	} while (len);
	return i;
}
#endif


int get_user_pages_uprobe(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, int len, int write, int force,
		struct page **pages, struct vm_area_struct **vmas)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	int flags = 0;

	if (write)
		flags |= GUP_FLAGS_WRITE;
	if (force)
		flags |= GUP_FLAGS_FORCE;

	return __get_user_pages_uprobe(tsk, mm,
				start, len, flags,
				pages, vmas);
#else
	return get_user_pages(tsk, mm, start, len, write, force, pages, vmas);
#endif
}

int access_process_vm_atomic(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	void *old_buf = buf;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	//down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages_uprobe(tsk, mm, addr, 1,
				write, 1, &page, &vma);
		if (ret <= 0) {
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
#ifdef CONFIG_HAVE_IOREMAP_PROT
			vma = find_vma(mm, addr);
			if (!vma)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
#endif
				break;
			bytes = ret;
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	//up_read(&mm->mmap_sem);
	mmput(mm);

	return buf - old_buf;
}

int page_present (struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep, pte;
        unsigned long pfn;

        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto out;

        pud = pud_offset(pgd, address);
        if (pud_none(*pud) || unlikely(pud_bad(*pud)))
                goto out;

        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
                goto out;

        ptep = pte_offset_map(pmd, address);
        if (!ptep)
                goto out;

        pte = *ptep;
        pte_unmap(ptep);
        if (pte_present(pte)) {
                pfn = pte_pfn(pte);
                if (pfn_valid(pfn)) {
                        return 1;
                }
        }

out:
        return 0;
}


EXPORT_SYMBOL_GPL (page_present);
EXPORT_SYMBOL_GPL (get_user_pages_uprobe);
EXPORT_SYMBOL_GPL (access_process_vm_atomic);

