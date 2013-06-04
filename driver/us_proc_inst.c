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
#include "filters/filter_by_path.h"
#include "helper.h"
#include "us_slot_manager.h"

#define print_event(fmt, args...) 						\
{ 										\
	char *buf[1024];							\
	sprintf(buf, fmt, ##args);						\
	pack_event_info(US_PROBE_ID, RECORD_ENTRY, "ds", 0x0badc0de, buf);	\
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
