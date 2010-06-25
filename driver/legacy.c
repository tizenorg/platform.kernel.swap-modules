////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           legacy.c
//
//      DESCRIPTION:
//      This file is C source for SWAP driver.
//
//      SEE ALSO:       legacy.h
//      AUTHOR:         L.Komkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.02
//
////////////////////////////////////////////////////////////////////////////////////

#include "module.h"
#include "legacy.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
signed long
schedule_timeout_interruptible (signed long timeout)
{
	__set_current_state (TASK_INTERRUPTIBLE);
	return schedule_timeout (timeout);
}
#endif /* kernel without schedule_timeout_interruptible */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
int
remap_vmalloc_range (struct vm_area_struct *vma, void *addr, unsigned long pgoff)
{
	unsigned long uaddr = vma->vm_start;
	unsigned long usize = vma->vm_end - vma->vm_start;
	int ret = -EINVAL;

	if ((PAGE_SIZE - 1) & (unsigned long) addr)
	{
		return -EINVAL;
	}

	if (pgoff)
	{
		return -EINVAL;
	}

	while (usize)
	{
		ret = remap_pfn_range (vma, uaddr, vmalloc_to_pfn (addr), PAGE_SIZE, PAGE_SHARED);
		if (ret)
		{
			break;
		}
		uaddr += PAGE_SIZE;
		addr += PAGE_SIZE;
		usize -= PAGE_SIZE;
	};

	return ret;
}
#endif /* kernel without remap_vmalloc_range() */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
/*
    To be mappable to user space, pages of memory allocated via "vmalloc" must
    be marked with "PG_reserved" flag. Memory allocated via "vmalloc_user"
    doesn't need it.
*/
static void
_reserve_pages (void *p, unsigned size)
{
	unsigned pages = (size + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
	while (pages)
	{
		SetPageReserved (vmalloc_to_page (p));

		p += PAGE_SIZE;
		--pages;
	}
}

static void
_unreserve_pages (void *p, unsigned size)
{
	unsigned pages = (size + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
	while (pages)
	{
		ClearPageReserved (vmalloc_to_page (p));

		p += PAGE_SIZE;
		--pages;
	}
}

void *
vmalloc_user (unsigned long size)
{
	void *p = __vmalloc (size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
	if (p)
	{
		memset (p, 0, size);
		_reserve_pages (p, size);
	}
	return p;
}

void
vfree_user (void *address, unsigned long size)
{
	_unreserve_pages (address, size);
	vfree (address);
}
#endif /* kernel without vmalloc_user() */
