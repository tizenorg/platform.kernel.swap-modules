////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           legacy.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       legacy.c
//      AUTHOR:         L.Komkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

/*
    Support for legacy Linux kernel versions
*/
#if !defined(__LEGACY_H__)
#define __LEGACY_H__

#include <linux/mm.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
extern signed long schedule_timeout_interruptible (signed long timeout);
#endif /* kernel without schedule_timeout_interruptible */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
extern int remap_vmalloc_range (struct vm_area_struct *vma, void *addr, unsigned long pgoff);
#endif /* kernel without remap_vmalloc_range() */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18)
extern void *vmalloc_user (unsigned long size);
extern void vfree_user (void *address, unsigned long size);
#define VFREE_USER(address, size) \
	{ \
		if(address != NULL) { \
			vfree_user(address, size); \
			address = NULL; \
		} \
	}
#else
#define VFREE_USER(address, size) \
	{ \
		if(address != NULL) { \
			vfree(address); \
			address = NULL; \
		} \
	}
#endif /* kernel without vmalloc_user() */

#endif /* !defined(__LEGACY_H__) */
