////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           storage.c
//
//      DESCRIPTION:
//      This file is C source for SWAP.
//
//      SEE ALSO:       storage.h
//      AUTHOR:         L.Komkov, S.Dianov, A.Gerenkov, S.Andreev
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include <linux/types.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/unistd.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <ksyms.h>
#include <dbi_kprobes_deps.h>
#include "module.h"
#include "storage.h"
#include "handlers_core.h"
#include "CProfile.h"
#include "sspt/sspt.h"
#include "sspt/sspt_debug.h"

#define after_buffer ec_info.buffer_size

char *p_buffer = NULL;
inst_us_proc_t us_proc_info;
inst_dex_proc_t dex_proc_info;
char *deps;
char *bundle;
unsigned int inst_pid = 0;
struct hlist_head kernel_probes;
struct hlist_head otg_kernel_probes;
int event_mask = 0L;
struct cond cond_list;
int paused = 0; /* a state after a stop condition (events are not collected) */
struct timeval last_attach_time = {0, 0};

static struct dbi_modules_handlers dbi_mh;

struct dbi_modules_handlers *get_dbi_modules_handlers(void)
{
	return &dbi_mh;
}
EXPORT_SYMBOL_GPL(get_dbi_modules_handlers);

inline unsigned long find_dbi_jp_handler(unsigned long p_addr, struct dbi_modules_handlers_info *mhi)
{
	int i;

	/* Possibly we can find less expensive way */
	for (i = 0; i < mhi->dbi_nr_handlers; i++) {
		if (mhi->dbi_handlers[i].func_addr == p_addr) {
			printk("Found jp_handler for %0lX address of %s module\n", p_addr, mhi->dbi_module->name);
			return mhi->dbi_handlers[i].jp_handler_addr;
		}
	}
	return 0;
}

inline unsigned long find_dbi_rp_handler(unsigned long p_addr, struct dbi_modules_handlers_info *mhi)
{
	int i;

	/* Possibly we can find less expensive way */
	for (i = 0; i < mhi->dbi_nr_handlers; i++) {
		if (mhi->dbi_handlers[i].func_addr == p_addr) {
			printk("Found rp_handler for %0lX address of %s module\n", p_addr, mhi->dbi_module->name);
			return mhi->dbi_handlers[i].rp_handler_addr;
		}
	}
	return 0;
}

/**
 * Search of handler in global list of modules for defined probe
 */
static void dbi_find_and_set_handler_for_probe(kernel_probe_t *p)
{
	unsigned long jp_handler_addr, rp_handler_addr;
	struct dbi_modules_handlers_info *local_mhi;
	unsigned long dbi_flags;
	unsigned int local_module_refcount = 0;

	spin_lock_irqsave(&dbi_mh.lock, dbi_flags);
	list_for_each_entry_rcu(local_mhi, &dbi_mh.modules_handlers, dbi_list_head) {
		printk("Searching handlers in %s module for %0lX address\n",
			(local_mhi->dbi_module)->name, p->addr);
		// XXX: absent code for pre_handlers because we suppose that they are not used
		if ((jp_handler_addr = find_dbi_jp_handler(p->addr, local_mhi)) != 0) {
			if (p->jprobe.entry != NULL) {
				printk("Skipping jp_handler for %s module (address %0lX)\n",
						(local_mhi->dbi_module)->name, p->addr);
			}
			else {
				local_module_refcount = module_refcount(local_mhi->dbi_module);
				if (local_module_refcount == 0) {
					if (!try_module_get(local_mhi->dbi_module))
						printk("Error of try_module_get() for module %s\n",
								(local_mhi->dbi_module)->name);
					else
						printk("Module %s in use now\n",
								(local_mhi->dbi_module)->name);
				}
				p->jprobe.entry = (kprobe_opcode_t *)jp_handler_addr;
				printk("Set jp_handler for %s module (address %0lX)\n",
						(local_mhi->dbi_module)->name, p->addr);
			}
		}
		if ((rp_handler_addr = find_dbi_rp_handler(p->addr, local_mhi)) != 0) {
			if (p->retprobe.handler != NULL) {
				printk("Skipping kretprobe_handler for %s module (address %0lX)\n",
						(local_mhi->dbi_module)->name, p->addr);
			}
			else {
				local_module_refcount = module_refcount(local_mhi->dbi_module);
				if (local_module_refcount == 0) {
					if (!try_module_get(local_mhi->dbi_module))
						printk("Error of try_module_get() for module %s\n",
								(local_mhi->dbi_module)->name);
					else
						printk("Module %s in use now\n",
								(local_mhi->dbi_module)->name);
				}
				p->retprobe.handler = (kretprobe_handler_t)rp_handler_addr;
				printk("Set rp_handler for %s module (address %0lX)\n",
						(local_mhi->dbi_module)->name, p->addr);
			}
		}
	}
	// not found pre_handler - set default (always true for now since pre_handlers not used)
	if (p->jprobe.pre_entry == NULL) {
		p->jprobe.pre_entry = (kprobe_pre_entry_handler_t) def_jprobe_event_pre_handler;
		printk("Set default pre_handler (address %0lX)\n", p->addr);
	}
	// not found jp_handler - set default
	if (p->jprobe.entry == NULL) {
		p->jprobe.entry = (kprobe_opcode_t *) def_jprobe_event_handler;
		printk("Set default jp_handler (address %0lX)\n", p->addr);
	}
	// not found kretprobe_handler - set default
	if (p->retprobe.handler == NULL) {
		p->retprobe.handler = (kretprobe_handler_t) def_retprobe_event_handler;
		printk("Set default rp_handler (address %0lX)\n", p->addr);
	}
	spin_unlock_irqrestore(&dbi_mh.lock, dbi_flags);
}

// XXX TODO: possible mess when start-register/unregister-stop operation
// so we should refuse register/unregister operation while we are in unsafe state
int dbi_register_handlers_module(struct dbi_modules_handlers_info *dbi_mhi)
{
	unsigned long dbi_flags;
//	struct dbi_modules_handlers_info *local_mhi;
	int i=0;
	int nr_handlers=dbi_mhi->dbi_nr_handlers;

	for (i = 0; i < nr_handlers; ++i) {
		dbi_mhi->dbi_handlers[i].func_addr = swap_ksyms(dbi_mhi->dbi_handlers[i].func_name);
		printk("[0x%08lx]-%s\n", dbi_mhi->dbi_handlers[i].func_addr, dbi_mhi->dbi_handlers[i].func_name);
	}

	spin_lock_irqsave(&dbi_mh.lock, dbi_flags);
//	local_mhi = container_of(&dbi_mhi->dbi_list_head, struct dbi_modules_handlers_info, dbi_list_head);
	list_add_rcu(&dbi_mhi->dbi_list_head, &dbi_mh.modules_handlers);
	printk("Added module %s (head is %p)\n", (dbi_mhi->dbi_module)->name, &dbi_mhi->dbi_list_head);
	spin_unlock_irqrestore(&dbi_mh.lock, dbi_flags);
	return 0;
}
EXPORT_SYMBOL_GPL(dbi_register_handlers_module);

// XXX TODO: possible mess when start-register/unregister-stop operation
// so we should refuse register/unregister operation while we are in unsafe state
int dbi_unregister_handlers_module(struct dbi_modules_handlers_info *dbi_mhi)
{
	unsigned long dbi_flags;
	// Next code block is for far future possible usage in case when removing will be implemented for unsafe state
	// (i.e. between attach and stop)
	/*kernel_probe_t *p;
	struct hlist_node *node;
	unsigned long jp_handler_addr, rp_handler_addr, pre_handler_addr;*/

	spin_lock_irqsave(&dbi_mh.lock, dbi_flags);
	list_del_rcu(&dbi_mhi->dbi_list_head);
	// Next code block is for far future possible usage in case when removing will be implemented for unsafe state
	// (i.e. between attach and stop)
	/*swap_hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist) {
		// XXX: absent code for pre_handlers because we suppose that they are not used
		if ((p->jprobe.entry != ((kprobe_pre_entry_handler_t )def_jprobe_event_pre_handler)) ||
				(p->retprobe.handler != ((kretprobe_handler_t )def_retprobe_event_handler))) {
			printk("Searching handlers for %p address for removing in %s registered module...\n",
					p->addr, (dbi_mhi->dbi_module)->name);
			jp_handler_addr = find_dbi_jp_handler(p->addr, dbi_mhi);
			rp_handler_addr = find_dbi_rp_handler(p->addr, dbi_mhi);
			if ((jp_handler_addr != 0) || (rp_handler_addr != 0)) {
				// search and set to another handlers or default
				dbi_find_and_set_handler_for_probe(p);
				printk("Removed handler(s) for %s module (address %p)\n",
						(dbi_mhi->dbi_module)->name, p->addr);
			}
		}
	}*/
	printk("Removed module %s (head was %p)\n", (dbi_mhi->dbi_module)->name, &dbi_mhi->dbi_list_head);
	spin_unlock_irqrestore(&dbi_mh.lock, dbi_flags);
	return 0;
}
EXPORT_SYMBOL_GPL(dbi_unregister_handlers_module);

static inst_us_proc_t empty_uprobes_info =
{
	.libs_count = 0,
	.p_libs = NULL,
};

static inst_us_proc_t *get_uprobes(void)
{
	unsigned long dbi_flags;
	inst_us_proc_t *ret = &empty_uprobes_info;
	struct dbi_modules_handlers_info *mhi;
	struct list_head *head = &dbi_mh.modules_handlers;

	spin_lock_irqsave(&dbi_mh.lock, dbi_flags);
	list_for_each_entry_rcu(mhi, head, dbi_list_head) {
		if (mhi->get_uprobes) {
			ret = mhi->get_uprobes();
			break;
		}
	}
	spin_unlock_irqrestore(&dbi_mh.lock, dbi_flags);

	return ret;
}

EXPORT_SYMBOL_GPL(us_proc_info);
EXPORT_SYMBOL_GPL(dex_proc_info);
typedef void *(*get_my_uprobes_info_t)(void);
#ifdef MEMORY_CHECKER
typedef int (*mec_post_event_pointer)(char *data, unsigned long len);
static mec_post_event_pointer mec_post_event = NULL;
#endif

static unsigned copy_into_cyclic_buffer (char *buffer, unsigned dst_offset,
										 char *src, unsigned size)
{
	memcpy(buffer + dst_offset, src, size);
	return dst_offset + size;
}

static int CheckBufferSize (unsigned int nSize)
{
	if (nSize < EC_BUFFER_SIZE_MIN) {
		EPRINTF("Too small buffer size! [Size=%u KB]", nSize / 1024);
		return -1;
	}
	if (nSize > EC_BUFFER_SIZE_MAX) {
		EPRINTF("Too big buffer size! [Size=%u KB]", nSize / 1024);
		return -1;
	}
	return 0;
}

static int AllocateSingleBuffer(unsigned int nSize)
{
	unsigned long spinlock_flags = 0L;

	p_buffer = vmalloc_user(nSize);
	if(!p_buffer) {
		EPRINTF("Memory allocation error! [Size=%u KB]", nSize / 1024);
		return -1;
	}

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.buffer_effect = ec_info.buffer_size = nSize;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

static void FreeSingleBuffer (void)
{
	VFREE_USER(p_buffer, ec_info.buffer_size);
	CleanECInfo();
}

//////////////////////////////////////////////////////////////////////////////////////////////////

int EnableContinuousRetrieval(void)
{
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode |= MODEMASK_CONTINUOUS_RETRIEVAL;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

int DisableContinuousRetrieval(void)
{
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode &= ~MODEMASK_CONTINUOUS_RETRIEVAL;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////

static int InitializeBuffer(unsigned int nSize) {
	return AllocateSingleBuffer(nSize);
}

static int UninitializeBuffer(void) {
	FreeSingleBuffer();
	return 0;
}

unsigned int GetBufferSize(void) { return ec_info.buffer_size; };

int SetBufferSize(unsigned int nSize) {
	if (GetECState() != EC_STATE_IDLE) {
		EPRINTF("Buffer changes are allowed in IDLE state only (%d)!", GetECState());
		return -1;
	}
	if(GetBufferSize() == nSize)
		return 0;
	if(CheckBufferSize(nSize) == -1) {
		EPRINTF("Invalid buffer size!");
		return -1;
	}
	detach_selected_probes ();
	if(UninitializeBuffer() == -1)
		EPRINTF("Cannot uninitialize buffer!");
	if(InitializeBuffer(nSize) == -1) {
		EPRINTF("Cannot initialize buffer! [Size=%u KB]", nSize / 1024);
		return -1;
	}
	return 0;
}

int SetPid(unsigned int pid)
{
	if (GetECState() != EC_STATE_IDLE)
	{
		EPRINTF("PID changes are allowed in IDLE state only (%d)!", GetECState());
		return -1;
	}

	inst_pid = pid;
	DPRINTF("SetPid pid:%d\n", pid);
	return 0;
}

static void ResetSingleBuffer(void) {
}

int ResetBuffer(void) {
	unsigned long spinlock_flags = 0L;

	if (GetECState() != EC_STATE_IDLE) {
		EPRINTF("Buffer changes are allowed in IDLE state only!");
		return -1;
	}

	ResetSingleBuffer();

	detach_selected_probes ();

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.buffer_effect = ec_info.buffer_size;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	ResetECInfo();

	return 0;
}

static int WriteEventIntoSingleBuffer(char* pEvent, unsigned long nEventSize) {
	unsigned int unused_space;

	if(!p_buffer) {
		EPRINTF("Invalid pointer to buffer!");
		++ec_info.lost_events_count;
		return -1;
	}
	if (ec_info.trace_size == 0 || ec_info.after_last > ec_info.first) {
		unused_space = ec_info.buffer_size - ec_info.after_last;
		if (unused_space > nEventSize) {
			ec_info.after_last = copy_into_cyclic_buffer(p_buffer,
														 ec_info.after_last,
														 pEvent,
														 nEventSize);
			ec_info.saved_events_count++;
			ec_info.buffer_effect = ec_info.buffer_size;
			ec_info.trace_size = ec_info.after_last - ec_info.first;
		} else {
			if (ec_info.first > nEventSize) {
				ec_info.buffer_effect = ec_info.after_last;
				ec_info.after_last = copy_into_cyclic_buffer(p_buffer,
															 0,
															 pEvent,
															 nEventSize);
				ec_info.saved_events_count++;
				ec_info.trace_size = ec_info.buffer_effect
					- ec_info.first
					+ ec_info.after_last;
			} else {
				// TODO: consider two variants!
				// Do nothing
				ec_info.discarded_events_count++;
			}
		}
	} else {
		unused_space = ec_info.first - ec_info.after_last;
		if (unused_space > nEventSize) {
			ec_info.after_last = copy_into_cyclic_buffer(p_buffer,
														 ec_info.after_last,
														 pEvent,
														 nEventSize);
			ec_info.saved_events_count++;
			ec_info.trace_size = ec_info.buffer_effect
				- ec_info.first
				+ ec_info.after_last;
		} else {
			// Do nothing
			ec_info.discarded_events_count++;
		}
	}
	return 0;
}

static int WriteEventIntoBuffer(char* pEvent, unsigned long nEventSize) {

	/*unsigned long i;
	for(i = 0; i < nEventSize; i++)
		printk("%02X ", pEvent[i]);
	printk("\n");*/

	return WriteEventIntoSingleBuffer(pEvent, nEventSize);
}

//////////////////////////////////////////////////////////////////////////////////////////////////

int set_event_mask (int new_mask)
{
	unsigned long spinlock_flags = 0L;
	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	event_mask = new_mask;
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
	return 0;
}

int
get_event_mask (int *mask)
{
	*mask = event_mask;
	return 0;
}

static void
generic_swap (void *a, void *b, int size)
{
	char t;
	do {
		t = *(char *) a;
		*(char *) a++ = *(char *) b;
		*(char *) b++ = t;
	} while (--size > 0);
}

static void sort (void *base, size_t num, size_t size, int (*cmp) (const void *, const void *), void (*fswap) (void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num / 2) * size, n = num * size, c, r;

	/* heapify */
	for (; i >= 0; i -= size)
	{
		for (r = i; r * 2 < n; r = c)
		{
			c = r * 2;
			if (c < n - size && cmp (base + c, base + c + size) < 0)
				c += size;
			if (cmp (base + r, base + c) >= 0)
				break;
			fswap (base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i >= 0; i -= size)
	{
		fswap (base, base + i, size);
		for (r = 0; r * 2 < i; r = c)
		{
			c = r * 2;
			if (c < i - size && cmp (base + c, base + c + size) < 0)
				c += size;
			if (cmp (base + r, base + c) >= 0)
				break;
			fswap (base + r, base + c, size);
		}
	}
}

static int addr_cmp (const void *a, const void *b)
{
	return *(unsigned long *) a > *(unsigned long *) b ? -1 : 1;
}

static char *find_lib_path(const char *lib_name)
{
	char *p = deps + sizeof(size_t);
	char *match;
	size_t len;

	while (*p != '\0') {
		DPRINTF("p is at %s", p);
		len = strlen(p) + 1;
		match = strstr(p, lib_name);
		p += len;
		len = strlen(p) + 1; /* we are at path now */
	    if (!match) {
			p += len;
		} else {
			DPRINTF("Found match: %s", match);
			return p;
		}
	}

	return NULL;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 27)
#define list_for_each_rcu(pos, head) __list_for_each_rcu(pos, head)
#endif

void unlink_bundle(void)
{
	int i, k;
	us_proc_lib_t *d_lib;
	char *path;
	struct list_head *pos;	//, *tmp;

	path = us_proc_info.path;
	us_proc_info.path = NULL;

	// first make sure "d_lib" is not used any more and only
	// then release storage
	if (us_proc_info.p_libs)
	{
		int count1 = us_proc_info.libs_count;
		us_proc_info.libs_count = 0;
		for (i = 0; i < count1; i++)
		{
			d_lib = &us_proc_info.p_libs[i];
			if (d_lib->p_ips)
			{
				// first make sure "d_lib->p_ips" is not used any more and only
				// then release storage
				//int count2 = d_lib->ips_count;
				d_lib->ips_count = 0;
				/*for (k = 0; k < count2; k++)
					kfree ((void *) d_lib->p_ips[k].name);*/
				vfree ((void *) d_lib->p_ips);
			}
			if (d_lib->p_vtps)
			{
				// first make sure "d_lib->p_vtps" is not used any more and only
				// then release storage
				int count2 = d_lib->vtps_count;
				d_lib->vtps_count = 0;
				for (k = 0; k < count2; k++)
				{
					//list_for_each_safe_rcu(pos, tmp, &d_lib->p_vtps[k].list) {
					list_for_each (pos, &d_lib->p_vtps[k].list)
					{
						us_proc_vtp_data_t *vtp = list_entry (pos, us_proc_vtp_data_t, list);
						list_del_rcu (pos);
						//kfree (vtp->name);
						kfree (vtp);
					}
				}
				kfree ((void *) d_lib->p_vtps);
			}
			d_lib->plt_count = 0;
			kfree((void*) d_lib->p_plt);
			us_proc_info.is_plt = 0;
		}
		kfree ((void *) us_proc_info.p_libs);
		us_proc_info.p_libs = NULL;
	}
	/* if (path) */
	/* { */
	/* 	kfree ((void *) path); */
	/* 	//putname(path); */
	/* } */

	us_proc_info.tgid = 0;
}

extern struct dentry *dentry_by_path(const char *path);

int link_bundle(void)
{
	inst_us_proc_t *my_uprobes_info = get_uprobes();
	char *p = bundle; /* read pointer for bundle */
	int nr_kern_probes;
	int i, j, l, k;
	int len;
	us_proc_lib_t *d_lib, *pd_lib;
	ioctl_usr_space_lib_t s_lib;
	ioctl_usr_space_vtp_t *s_vtp;
	us_proc_vtp_t *mvtp;
	int is_app = 0;
	char *ptr;
	us_proc_ip_t *d_ip;
	struct cond *c, *c_tmp, *p_cond;
	size_t nr_conds;
	int lib_name_len;
	int handler_index;

	DPRINTF("Going to release us_proc_info");
	if (us_proc_info.path)
		unlink_bundle();

	/* Skip size - it has been used before */
	p += sizeof(u_int32_t);

	/* Set mode */
	if (SetECMode(*(u_int32_t *)p) == -1)
	{
		EPRINTF("Cannot set mode!\n");
		return -1;
	}

	p += sizeof(u_int32_t);

	/* Buffer size */
	if (SetBufferSize(*(u_int32_t *)p) == -1)
	{
		EPRINTF("Cannot set buffer size!\n");
		return -1;
	}

	p += sizeof(u_int32_t);

	/* Pid */
	if (SetPid(*(u_int32_t *)p) == -1)
	{
		EPRINTF("Cannot set pid!\n");
		return -1;
	}

	p += sizeof(u_int32_t);

	/* Kernel probes */
	nr_kern_probes = *(u_int32_t *)p;
	p += sizeof(u_int32_t);
	for (i = 0; i < nr_kern_probes; i++)
	{
		if (add_probe(*(u_int32_t *)p))
		{
			EPRINTF("Cannot add kernel probe at 0x%x!\n", *(u_int32_t *)p);
			return -1;
		}
		p += sizeof(u_int32_t);
	}

	/* Us probes */
	len = *(u_int32_t *)p; /* App path len */
	p += sizeof(u_int32_t);

	us_proc_info.is_plt = 0;
	if ( len == 0 )
	{
	    us_proc_info.path = NULL;
	}
	else
	{
		int lib_path_len;
		char *lib_path;

		us_proc_info.path = (char *)p;
		DPRINTF("app path = %s", us_proc_info.path);
		p += len;

		if (strcmp(us_proc_info.path, "*")) {
			us_proc_info.m_f_dentry = dentry_by_path(us_proc_info.path);
			if (us_proc_info.m_f_dentry == NULL) {
				update_errno_buffer(us_proc_info.path, IS_APP);
				return -1;
			}
		}
		else
		{
			us_proc_info.m_f_dentry = NULL;
		}

		us_proc_info.libs_count = *(u_int32_t *)p;
		DPRINTF("nr of libs = %d", us_proc_info.libs_count);
		p += sizeof(u_int32_t);
		us_proc_info.p_libs =
			kmalloc(us_proc_info.libs_count * sizeof(us_proc_lib_t), GFP_KERNEL);

		if (!us_proc_info.p_libs)
		{
			EPRINTF("Cannot alloc p_libs!");
			return -1;
		}
		memset(us_proc_info.p_libs, 0,
			   us_proc_info.libs_count * sizeof(us_proc_lib_t));

		for (i = 0; i < us_proc_info.libs_count; i++)
		{
			int abs_handler_idx = 0;

			d_lib = &us_proc_info.p_libs[i];

			lib_name_len = *(u_int32_t *)p;
			p += sizeof(u_int32_t);
			d_lib->path = (char *)p;
			DPRINTF("d_lib->path = %s", d_lib->path);
			p += lib_name_len;

			if ( i != 0 ) {
				lib_name_len = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				d_lib->path_dyn = (char *)p;
				DPRINTF("d_lib->path_dyn = %s", d_lib->path_dyn);
				p += lib_name_len;
			}

			d_lib->ips_count = *(u_int32_t *)p;
			DPRINTF("d_lib->ips_count = %d", d_lib->ips_count);
			p += sizeof(u_int32_t);

			/* If there are any probes for "*" app we have to drop them */
			if (strcmp(d_lib->path, "*") == 0)
			{
				p += d_lib->ips_count * 3 * sizeof(u_int32_t);
				d_lib->ips_count = 0;
				d_lib->plt_count = *(u_int32_t*)p;
				p += sizeof(u_int32_t);
				p += d_lib->plt_count * 2 * sizeof(u_int32_t);
				d_lib->plt_count = 0;
				continue;
			}

			if (strcmp(us_proc_info.path, d_lib->path) == 0)
				is_app = 1;
			else
			{
				is_app = 0;
				DPRINTF("Searching path for lib %s", d_lib->path);
				d_lib->path = find_lib_path(d_lib->path);
				if (!d_lib->path)
				{
					if (strcmp(d_lib->path_dyn, "") == 0) {
						EPRINTF("Cannot find path for lib %s!", d_lib->path);
						if (update_errno_buffer(d_lib->path, IS_LIB) == -1) {
							return -1;
						}
						/* Just skip all the IPs and go to next lib */
						p += d_lib->ips_count * 3 * sizeof(u_int32_t);
						d_lib->ips_count = 0;
						d_lib->plt_count = *(u_int32_t*)p;
						p += sizeof(u_int32_t);
						p += d_lib->plt_count * 2 * sizeof(u_int32_t);
						d_lib->plt_count = 0;
						continue;
					}
					else {
						d_lib->path = d_lib->path_dyn;
						DPRINTF("Assign path for lib as %s (in suggestion of dyn lib)", d_lib->path);
					}
				}
			}

			d_lib->m_f_dentry = dentry_by_path(d_lib->path);
			if (d_lib->m_f_dentry == NULL) {
				EPRINTF ("failed to lookup dentry for path %s!", d_lib->path);
				if (update_errno_buffer(d_lib->path, IS_LIB) == -1) {
					return -1;
				}
				/* Just skip all the IPs and go to next lib */
				p += d_lib->ips_count * 3 * sizeof(u_int32_t);
				d_lib->ips_count = 0;
				d_lib->plt_count = *(u_int32_t*)p;
				p += sizeof(u_int32_t);
				p += d_lib->plt_count * 2 * sizeof(u_int32_t);
				d_lib->plt_count = 0;
				continue;
			}

			pd_lib = NULL;
			ptr = strrchr(d_lib->path, '/');
			if (ptr)
				ptr++;
			else
				ptr = d_lib->path;

			for (l = 0; l < my_uprobes_info->libs_count; l++)
			{
				if ((strcmp(ptr, my_uprobes_info->p_libs[l].path) == 0) ||
					(is_app && *(my_uprobes_info->p_libs[l].path) == '\0'))
				{
					pd_lib = &my_uprobes_info->p_libs[l];
					break;
				}
				abs_handler_idx += my_uprobes_info->p_libs[l].ips_count;
			}

			if (d_lib->ips_count > 0)
			{
				us_proc_info.unres_ips_count += d_lib->ips_count;
				d_lib->p_ips = vmalloc(d_lib->ips_count * sizeof(us_proc_ip_t));
				DPRINTF("d_lib[%i]->p_ips=%p/%u [%s]", i, d_lib->p_ips,
						us_proc_info.unres_ips_count, d_lib->path);

				if (!d_lib->p_ips)
				{
					EPRINTF("Cannot alloc p_ips!\n");
					return -1;
				}

				memset (d_lib->p_ips, 0, d_lib->ips_count * sizeof(us_proc_ip_t));
				for (k = 0; k < d_lib->ips_count; k++)
				{
					d_ip = &d_lib->p_ips[k];
					d_ip->offset = *(u_int32_t *)p;
					p += sizeof(u_int32_t);
					p += sizeof(u_int32_t); /* Skip inst type */
					handler_index = *(u_int32_t *)p;
					p += sizeof(u_int32_t);

					if (pd_lib)
					{
						DPRINTF("pd_lib->ips_count = 0x%x", pd_lib->ips_count);
						if (handler_index != -1)
						{
							DPRINTF("found handler for 0x%x", d_ip->offset);
							d_ip->jprobe.pre_entry =
								pd_lib->p_ips[handler_index - abs_handler_idx].jprobe.pre_entry;
							d_ip->jprobe.entry =
								pd_lib->p_ips[handler_index - abs_handler_idx].jprobe.entry;
							d_ip->retprobe.handler =
								pd_lib->p_ips[handler_index - abs_handler_idx].retprobe.handler;
						}
					}
				}
			}

			d_lib->plt_count = *(u_int32_t*)p;
			p += sizeof(u_int32_t);
			if (d_lib->plt_count > 0)
			{
				int j;
				us_proc_info.is_plt = 1;
				d_lib->p_plt = kmalloc(d_lib->plt_count * sizeof(us_proc_plt_t), GFP_KERNEL);
				if (!d_lib->p_plt)
				{
					EPRINTF("Cannot alloc p_plt!");
					return -1;
				}
				memset(d_lib->p_plt, 0, d_lib->plt_count * sizeof(us_proc_plt_t));
				for (j = 0; j < d_lib->plt_count; j++)
				{
					d_lib->p_plt[j].func_addr = *(u_int32_t*)p;
					p += sizeof(u_int32_t);
					d_lib->p_plt[j].got_addr = *(u_int32_t*)p;
					p += sizeof(u_int32_t);
					d_lib->p_plt[j].real_func_addr = 0;
				}
			}
		}

		/* Lib path */
		lib_path_len = *(u_int32_t *)p;
		DPRINTF("lib_path_len = %d", lib_path_len);
		p += sizeof(u_int32_t);
		lib_path = p;
		DPRINTF("lib_path = %s", lib_path);
		p += lib_path_len;

		/* Link FBI info */
		d_lib = &us_proc_info.p_libs[0];
		s_lib.vtps_count = *(u_int32_t *)p;
		DPRINTF("s_lib.vtps_count = %d", s_lib.vtps_count);
		p += sizeof(u_int32_t);
		if (s_lib.vtps_count > 0)
		{
			unsigned long ucount = 1, pre_addr;
			unsigned long *addrs;

			s_lib.p_vtps = kmalloc(s_lib.vtps_count
								   * sizeof(ioctl_usr_space_vtp_t), GFP_KERNEL);
			if (!s_lib.p_vtps)
			{
				//kfree (addrs);
				return -1;
			}

			for (i = 0; i < s_lib.vtps_count; i++)
			{
				int var_name_len = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				s_lib.p_vtps[i].name = p;
				p += var_name_len;
				s_lib.p_vtps[i].addr = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				s_lib.p_vtps[i].type = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				s_lib.p_vtps[i].size = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				s_lib.p_vtps[i].reg = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
				s_lib.p_vtps[i].off = *(u_int32_t *)p;
				p += sizeof(u_int32_t);
			}

			// array containing elements like (addr, index)
			addrs = kmalloc (s_lib.vtps_count * 2 * sizeof (unsigned long), GFP_KERNEL);
	//			DPRINTF ("addrs=%p/%u", addrs, s_lib.vtps_count);
			if (!addrs)
			{
				//note: storage will released next time or at clean-up moment
				return -ENOMEM;
			}
			memset (addrs, 0, s_lib.vtps_count * 2 * sizeof (unsigned long));
			// fill the array in
			for (k = 0; k < s_lib.vtps_count; k++)
			{
				s_vtp = &s_lib.p_vtps[k];
				addrs[2 * k] = s_vtp->addr;
				addrs[2 * k + 1] = k;
			}
			// sort by VTP addresses, i.e. make VTPs with the same addresses adjacent;
			// organize them into bundles
			sort (addrs, s_lib.vtps_count, 2 * sizeof (unsigned long), addr_cmp, generic_swap);

			// calc number of VTPs with unique addresses
			for (k = 1, pre_addr = addrs[0]; k < s_lib.vtps_count; k++)
			{
				if (addrs[2 * k] != pre_addr)
					ucount++;	// count different only
				pre_addr = addrs[2 * k];
			}
			us_proc_info.unres_vtps_count += ucount;
			d_lib->vtps_count = ucount;
			d_lib->p_vtps = kmalloc (ucount * sizeof (us_proc_vtp_t), GFP_KERNEL);
			DPRINTF ("d_lib[%i]->p_vtps=%p/%lu", i, d_lib->p_vtps, ucount);	//, d_lib->path);
			if (!d_lib->p_vtps)
			{
				//note: storage will released next time or at clean-up moment
				kfree (addrs);
				return -ENOMEM;
			}
			memset (d_lib->p_vtps, 0, d_lib->vtps_count * sizeof (us_proc_vtp_t));
			// go through sorted VTPS.
			for (k = 0, j = 0, pre_addr = 0, mvtp = NULL; k < s_lib.vtps_count; k++)
			{
				us_proc_vtp_data_t *vtp_data;
				// copy VTP data
				s_vtp = &s_lib.p_vtps[addrs[2 * k + 1]];
				// if this is the first VTP in bundle (master VTP)
				if (addrs[2 * k] != pre_addr)
				{
					// data are in the array of master VTPs
					mvtp = &d_lib->p_vtps[j++];
					mvtp->addr = s_vtp->addr;
					INIT_LIST_HEAD (&mvtp->list);
				}
				// data are in the list of slave VTPs
				vtp_data = kmalloc (sizeof (us_proc_vtp_data_t), GFP_KERNEL);
				if (!vtp_data)
				{
					//note: storage will released next time or at clean-up moment
					kfree (addrs);
					return -ENOMEM;
				}

				/*len = strlen_user (s_vtp->name);
				  vtp_data->name = kmalloc (len, GFP_KERNEL);
				  if (!vtp_data->name)
				  {
				  //note: storage will released next time or at clean-up moment
				  kfree (vtp_data);
				  kfree (addrs);
				  return -ENOMEM;
				  }
				  if (strncpy_from_user (vtp_data->name, s_vtp->name, len) != (len-1))
				  {
				  //note: storage will released next time or at clean-up moment
				  EPRINTF ("strncpy_from_user VTP name failed %p (%ld)", vtp_data->name, len);
				  kfree (vtp_data->name);
				  kfree (vtp_data);
				  kfree (addrs);
				  return -EFAULT;
				  }
				  //vtp_data->name[len] = 0;*/
				vtp_data->name = s_vtp->name;
				vtp_data->type = s_vtp->type;
				vtp_data->size = s_vtp->size;
				vtp_data->reg = s_vtp->reg;
				vtp_data->off = s_vtp->off;
				list_add_tail_rcu (&vtp_data->list, &mvtp->list);
				pre_addr = addrs[2 * k];
			}
			kfree (addrs);
			kfree(s_lib.p_vtps);
		}
	}

	/* Conds */
	/* first, delete all the conds */
	list_for_each_entry_safe(c, c_tmp, &cond_list.list, list) {
		list_del(&c->list);
		kfree(c);
	}
	/* second, add new conds */
	/* This can be improved (by placing conds into array) */
	nr_conds = *(u_int32_t *)p;
	DPRINTF("nr_conds = %d", nr_conds);
	p += sizeof(u_int32_t);
	for (i = 0; i < nr_conds; i++) {
		p_cond = kmalloc(sizeof(struct cond), GFP_KERNEL);
		if (!p_cond) {
			EPRINTF("Cannot alloc cond!\n");
			return -1;
			break;
		}
		memcpy(&p_cond->tmpl, p, sizeof(struct event_tmpl));
		p_cond->applied = 0;
		list_add(&(p_cond->list), &(cond_list.list));
		p += sizeof(struct event_tmpl);
	}

	/* Event mask */
	if (set_event_mask(*(u_int32_t *)p)) {
		EPRINTF("Cannot set event mask!");
		return -1;
	}

	p += sizeof(u_int32_t);

	// print
//	print_inst_us_proc(&us_proc_info);

	us_proc_info.pp = get_file_probes(&us_proc_info);

	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++//
int storage_init (void)
{
	unsigned long spinlock_flags = 0L;

	spin_lock_irqsave (&ec_spinlock, spinlock_flags);
	ec_info.m_nMode = 0; // MASK IS CLEAR (SINGLE NON_CONTINUOUS BUFFER)
	spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);

	if(InitializeBuffer(EC_BUFFER_SIZE_DEFAULT) == -1) {
		EPRINTF("Cannot initialize buffer! [Size=%u KB]", EC_BUFFER_SIZE_DEFAULT / 1024 );
		return -1;
	}

	INIT_HLIST_HEAD(&kernel_probes);
	INIT_HLIST_HEAD(&otg_kernel_probes);

	spin_lock_init(&dbi_mh.lock);
	INIT_LIST_HEAD(&dbi_mh.modules_handlers);
	return 0;
}

/*
    Shuts down "storage".
    Assumes that all probes are already deactivated.
*/
void storage_down (void)
{
	if(UninitializeBuffer() == -1)
		EPRINTF("Cannot uninitialize buffer!");

	if (ec_info.collision_count)
		EPRINTF ("ec_info.collision_count=%d", ec_info.collision_count);
	if (ec_info.lost_events_count)
		EPRINTF ("ec_info.lost_events_count=%d", ec_info.lost_events_count);
}

static u_int32_t get_probe_func_addr(const char *fmt, va_list args)
{
	if (fmt[0] != 'p')
		return 0;

	return va_arg(args, u_int32_t);
}

void pack_task_event_info(struct task_struct *task, probe_id_t probe_id,
		record_type_t record_type, const char *fmt, ...)
{
	unsigned long spinlock_flags = 0L;
	static char buf[EVENT_MAX_SIZE] = "";
	TYPEOF_EVENT_LENGTH event_len = 0L;
	struct timeval tv = { 0, 0 };
	TYPEOF_THREAD_ID current_pid = task->pid;
	TYPEOF_PROCESS_ID current_tgid = task->tgid;
	unsigned current_cpu = task_cpu(task);
	va_list args;
	unsigned long addr = 0;
	struct cond *p_cond;
	struct event_tmpl *p_tmpl;

	do_gettimeofday (&tv);

	if (probe_id == KS_PROBE_ID) {
		va_start(args, fmt);
		addr = get_probe_func_addr(fmt, args);
		va_end(args);
	}
	if (probe_id == US_PROBE_ID) {
		va_start(args, fmt);
		addr = get_probe_func_addr(fmt, args);
		va_end(args);
	}

	/* Checking for all the conditions
	 * except stop condition that we process after saving the event */
	list_for_each_entry(p_cond, &cond_list.list, list) {
		p_tmpl = &p_cond->tmpl;
		switch (p_tmpl->type) {
		case ET_TYPE_START_COND:
			if ((!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_ADDR) ||
				 (addr == p_tmpl->addr)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_PID) ||
				 (current_tgid == p_tmpl->pid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TID) ||
				 (current_pid == p_tmpl->tid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_CPU_NUM) ||
				 (current_cpu == p_tmpl->cpu_num)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_BIN_NAME) ||
				 (strcmp(task->comm, p_tmpl->bin_name) == 0)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TIME) ||
				 (tv.tv_sec > last_attach_time.tv_sec + p_tmpl->sec) ||
				 (tv.tv_sec == last_attach_time.tv_sec + p_tmpl->sec &&
				  tv.tv_usec >= last_attach_time.tv_usec + p_tmpl->usec)) &&
				!p_cond->applied) {
				spin_lock_irqsave(&ec_spinlock, spinlock_flags);
				paused = 0;
				p_cond->applied = 1;
				spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
			}
			break;
		case ET_TYPE_IGNORE_COND:
			/* if (probe_id == PROBE_SCHEDULE) */
			/* 	break; */
			if ((!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_ADDR) ||
				 (addr == p_tmpl->addr)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_PID) ||
				 (current_tgid == p_tmpl->pid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TID) ||
				 (current_pid == p_tmpl->tid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_CPU_NUM) ||
				 (current_cpu == p_tmpl->cpu_num)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_BIN_NAME) ||
				 (strcmp(task->comm, p_tmpl->bin_name) == 0))) {
				spin_lock_irqsave(&ec_spinlock, spinlock_flags);
				ec_info.ignored_events_count++;
				spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
				return;
			}
			break;
		}
	}

	/* Save only not masked entry or return kernel and user space events */
	if (likely(!((probe_id == KS_PROBE_ID || probe_id == US_PROBE_ID)
		  && ((record_type == RECORD_ENTRY && (event_mask & IOCTL_EMASK_ENTRY))
			  || (record_type == RECORD_RET && (event_mask & IOCTL_EMASK_EXIT)))))) {

		spin_lock_irqsave (&ec_spinlock, spinlock_flags);

		if (paused && (!(probe_id == EVENT_FMT_PROBE_ID || probe_id == DYN_LIB_PROBE_ID))) {
			ec_info.ignored_events_count++;
			spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
			return;
		}

		va_start (args, fmt);
		event_len = VPackEvent(buf, sizeof(buf), event_mask, probe_id, record_type, (TYPEOF_TIME *)&tv,
							   current_tgid, current_pid, current_cpu, fmt, args);
		va_end (args);

		if(event_len == 0) {
			EPRINTF ("ERROR: failed to pack event!");
			++ec_info.lost_events_count;

		} else if(WriteEventIntoBuffer(buf, event_len) == -1) {
			EPRINTF("Cannot write event into buffer!");
			++ec_info.lost_events_count;
		}
		spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);

	}

	/* Check for stop condition.  We pause collecting the trace right after
	 * storing this event */
	list_for_each_entry(p_cond, &cond_list.list, list) {
		p_tmpl = &p_cond->tmpl;
		switch (p_tmpl->type) {
		case ET_TYPE_STOP_COND:
			if ((!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_ADDR) ||
				 (addr == p_tmpl->addr)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_PID) ||
				 (current_tgid == p_tmpl->pid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TID) ||
				 (current_pid == p_tmpl->tid)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_CPU_NUM) ||
				 (current_cpu == p_tmpl->cpu_num)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_BIN_NAME) ||
				(strcmp(task->comm, p_tmpl->bin_name) == 0)) &&
				(!ET_FIELD_ISSET(p_tmpl->flags, ET_MATCH_TIME) ||
				 (tv.tv_sec > last_attach_time.tv_sec + p_tmpl->sec) ||
				 (tv.tv_sec == last_attach_time.tv_sec + p_tmpl->sec &&
				  tv.tv_usec >= last_attach_time.tv_usec + p_tmpl->usec)) &&
				!p_cond->applied) {
				spin_lock_irqsave(&ec_spinlock, spinlock_flags);
				paused = 1;
				p_cond->applied = 1;
				spin_unlock_irqrestore(&ec_spinlock, spinlock_flags);
			}
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(pack_task_event_info);

kernel_probe_t* find_probe (unsigned long addr)
{
	kernel_probe_t *p;
	struct hlist_node *node;

	//check if such probe does exist
	swap_hlist_for_each_entry_rcu (p, node, &kernel_probes, hlist)
		if (p->addr == addr)
			break;

	return node ? p : NULL;
}


int add_probe_to_list (unsigned long addr, kernel_probe_t ** pprobe)
{
	kernel_probe_t *new_probe;
	kernel_probe_t *probe;

	if (pprobe)
		*pprobe = NULL;
	//check if such probe does already exist
	probe = find_probe(addr);
	if (probe) {
		/* It is not a problem if we have already registered
		   this probe before */
		return 0;
	}
	new_probe = kmalloc (sizeof (kernel_probe_t), GFP_KERNEL);
	if (!new_probe)
	{
		EPRINTF ("no memory for new probe!");
		return -ENOMEM;
	}
	memset (new_probe, 0, sizeof (kernel_probe_t));
	new_probe->addr = addr;
	new_probe->jprobe.kp.addr = new_probe->retprobe.kp.addr = (kprobe_opcode_t *)addr;
	new_probe->jprobe.priv_arg = new_probe->retprobe.priv_arg = new_probe;
	//new_probe->jprobe.pre_entry = (kprobe_pre_entry_handler_t) def_jprobe_event_pre_handler;
	dbi_find_and_set_handler_for_probe(new_probe);
	INIT_HLIST_NODE (&new_probe->hlist);
	hlist_add_head_rcu (&new_probe->hlist, &kernel_probes);
	if (pprobe)
		*pprobe = new_probe;
	return 0;
}

int remove_probe_from_list (unsigned long addr)
{
	kernel_probe_t *p;

	//check if such probe does exist
	p = find_probe (addr);
	if (!p) {
		/* We do not care about it. Nothing bad. */
		return 0;
	}

	hlist_del_rcu (&p->hlist);

	kfree (p);

	return 0;
}


int put_us_event (char *data, unsigned long len)
{
	unsigned long spinlock_flags = 0L;

	SWAP_TYPE_EVENT_HEADER *pEventHeader = (SWAP_TYPE_EVENT_HEADER *)data;
	char *cur = data + sizeof(TYPEOF_EVENT_LENGTH) + sizeof(TYPEOF_EVENT_TYPE)
				+ sizeof(TYPEOF_PROBE_ID);
	TYPEOF_NUMBER_OF_ARGS nArgs = pEventHeader->m_nNumberOfArgs;
	TYPEOF_PROBE_ID probe_id = pEventHeader->m_nProbeID;
	//int i;

	/*if(probe_id == US_PROBE_ID){
		printk("esrc %p/%d[", data, len);
		for(i = 0; i < len; i++)
			printk("%02x ", data[i]);
		printk("]\n");
	}*/

	// set pid/tid/cpu/time	i
	//pEventHeader->m_time.tv_sec = tv.tv_sec;
	//pEventHeader->m_time.tv_usec = tv.tv_usec;

#ifdef MEMORY_CHECKER
	//TODO: move this part to special MEC event posting routine, new IOCTL is needed
	if((probe_id >= MEC_PROBE_ID_MIN) && (probe_id <= MEC_PROBE_ID_MAX))
	{
		if(mec_post_event != NULL)
		{
			int res = mec_post_event(data, len);
			if(res == -1)
			{
				return -1;
			}
		}
		else
		{
			// FIXME: 'mec_post_event' - not found
			mec_post_event = (mec_post_event_pointer) swap_ksyms("mec_post_event");
			if(mec_post_event == NULL)
			{
				EPRINTF ("Failed to find function 'mec_post_event' from mec_handlers.ko. Memory Error Checker will work incorrectly.");
			}
			else
			{
				int res = mec_post_event(data, len);
				if(res == -1)
				{
					return -1;
				}
			}
		}
	}
#endif

	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_TIME)){
		struct timeval tv = { 0, 0 };
		do_gettimeofday (&tv);
		memcpy(cur, &tv, sizeof(TYPEOF_TIME));
		cur += sizeof(TYPEOF_TIME);
	}
	//pEventHeader->m_nProcessID = current_tgid;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_PID)){
		//TYPEOF_PROCESS_ID current_tgid = current->tgid;
		(*(TYPEOF_PROCESS_ID *)cur) = current->tgid;
		cur += sizeof(TYPEOF_PROCESS_ID);
	}
	//pEventHeader->m_nThreadID = current_pid;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_TID)){
		//TYPEOF_THREAD_ID current_pid = current->pid;
		(*(TYPEOF_THREAD_ID *)cur) = current->pid;
		cur += sizeof(TYPEOF_THREAD_ID);
	}
	//pEventHeader->m_nCPU = current_cpu;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(event_mask & IOCTL_EMASK_CPU)){
		//TYPEOF_CPU_NUMBER current_cpu = task_cpu(current);
		(*(TYPEOF_CPU_NUMBER *)cur) = task_cpu(current);
		cur += sizeof(TYPEOF_CPU_NUMBER);
	}
	//printk("%d %x", probe_id, event_mask);
	// dyn lib event should have all args, it is for internal use and not visible to user
	if((probe_id == EVENT_FMT_PROBE_ID) || (probe_id == DYN_LIB_PROBE_ID) || !(event_mask & IOCTL_EMASK_ARGS)){
		// move only if any of prev fields has been skipped
		if(event_mask & (IOCTL_EMASK_TIME|IOCTL_EMASK_PID|IOCTL_EMASK_TID|IOCTL_EMASK_CPU)){
			memmove(cur, data+sizeof(SWAP_TYPE_EVENT_HEADER)-sizeof(TYPEOF_NUMBER_OF_ARGS),
					len-sizeof(SWAP_TYPE_EVENT_HEADER)+sizeof(TYPEOF_NUMBER_OF_ARGS)
					-sizeof(TYPEOF_EVENT_LENGTH));
		}
		cur += len-sizeof(SWAP_TYPE_EVENT_HEADER)+sizeof(TYPEOF_NUMBER_OF_ARGS)
				-sizeof(TYPEOF_EVENT_LENGTH);
	}
	else{
		// user space probes should have at least one argument to identify them
		if((probe_id == US_PROBE_ID) || (probe_id == VTP_PROBE_ID)){
			char *pArg1;
			(*(TYPEOF_NUMBER_OF_ARGS *)cur) = 1;
			cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
			// pack args using format string for the 1st arg only
			memset(cur, 0, ALIGN_VALUE(2));
			cur[0] = 'p'; cur[1] = '\0';
			cur += ALIGN_VALUE(2);
			pArg1 = data + sizeof(SWAP_TYPE_EVENT_HEADER)+ALIGN_VALUE(nArgs+1);
			memmove(cur, pArg1, sizeof(unsigned long));
			cur += sizeof(unsigned long);
		}
		else {
			(*(TYPEOF_NUMBER_OF_ARGS *)cur) = 0;
			cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
		}
	}
	pEventHeader->m_nLength = cur - data + sizeof(TYPEOF_EVENT_LENGTH);
	*((TYPEOF_EVENT_LENGTH *)cur) = pEventHeader->m_nLength;
	len = pEventHeader->m_nLength;

	if(WriteEventIntoBuffer(data, len) == -1) {
		EPRINTF("Cannot write event into buffer!");

		spin_lock_irqsave (&ec_spinlock, spinlock_flags);
		++ec_info.lost_events_count;
		spin_unlock_irqrestore (&ec_spinlock, spinlock_flags);
	}

	return 0;
}


int get_predef_uprobes_size(int *size)
{
	int i, k;
	inst_us_proc_t *my_uprobes_info = get_uprobes();

	*size = 0;
	for(i = 0; i < my_uprobes_info->libs_count; i++)
	{
		int lib_size = strlen(my_uprobes_info->p_libs[i].path);
		for(k = 0; k < my_uprobes_info->p_libs[i].ips_count; k++)
		{
			// libc.so.6:printf:
			*size += lib_size + 1 + strlen(my_uprobes_info->p_libs[i].p_ips[k].name) + 2;
		}
	}

	return 0;
}

int get_predef_uprobes(ioctl_predef_uprobes_info_t *udata)
{
	ioctl_predef_uprobes_info_t data;
	int i, k, size, lib_size, func_size, result;
	unsigned count = 0;
	char sep[] = ":";
	inst_us_proc_t *my_uprobes_info = get_uprobes();

	// get addr of array
	if (copy_from_user ((void *)&data, (void __user *) udata, sizeof (data)))
	{
		EPRINTF("failed to copy from user!");
		return -EFAULT;
	}

	size = 0;
	for(i = 0; i < my_uprobes_info->libs_count; i++)
	{
		lib_size = strlen(my_uprobes_info->p_libs[i].path);
		for(k = 0; k < my_uprobes_info->p_libs[i].ips_count; k++)
		{
			// libname
			result = copy_to_user ((void __user *)(data.p_probes+size),
					(void *) my_uprobes_info->p_libs[i].path, lib_size);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size += lib_size;
			// ":"
			result = copy_to_user ((void __user *)(data.p_probes+size), sep, 1);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size++;
			// probename
			//DPRINTF("'%s'", my_uprobes_info->p_libs[i].p_ips[k].name);
			func_size = strlen(my_uprobes_info->p_libs[i].p_ips[k].name);
			result = copy_to_user ((void __user *)(data.p_probes+size), my_uprobes_info->p_libs[i].p_ips[k].name, func_size);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size += func_size;
			// ":\0"
			result = copy_to_user ((void __user *)(data.p_probes+size), sep, 2);
			if (result)
			{
				EPRINTF("failed to copy to user!");
				return -EFAULT;
			}
			size += 2;
			count++;
		}
	}

	// set probes_count
	result = copy_to_user ((void __user *)&(udata->probes_count), &count, sizeof(count));
	if (result)
	{
		EPRINTF("failed to copy to user!");
		return -EFAULT;
	}

	return 0;
}
