////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           storage.h
//
//      DESCRIPTION:
//      This file is C source for SWAP.
//
//      SEE ALSO:       storage.c
//      AUTHOR:         L.Komkov, S.Dianov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(__STORAGE_H__)
#define __STORAGE_H__

#include <linux/mount.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include "picl.h"
#include "ec_ioctl.h"
#include "ec_probe.h"
#include "probes_manager.h"
#include "probes.h"
#include "event_tmpl.h"

///////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __DISABLE_RELAYFS
extern struct rchan* GetRelayChannel(void);
extern struct dentry* GetRelayDir(void);
#endif //__DISABLE_RELAYFS

extern int EnableMultipleBuffer(void);
extern int DisableMultipleBuffer(void);
extern int EnableContinuousRetrieval(void);
extern int DisableContinuousRetrieval(void);

///////////////////////////////////////////////////////////////////////////////////////////////////

extern unsigned int GetBufferSize(void);
extern int SetBufferSize(unsigned int nSize);
extern int ResetBuffer(void);

extern int SetPid(unsigned int pid);

//extern spinlock_t buffer_spinlock;

///////////////////////////////////////////////////////////////////////////////////////////////////

/*
    Functions "storage_init()" and "storage_down()" are for initialization and
    shutdown respectively.
*/
extern int storage_init (void);
extern void storage_down (void);

/*
    Function "pack_event_info()" saves information about event into buffer. It
    is used in 'probes' to pack and save event data.
*/
extern void pack_event_info (probe_id_t probe_id, record_type_t record_type, const char *fmt, ...);

/* Set most links from us_proc_info to data in the bundle */
int link_bundle(void);

/* Undo the actions of link_bundle() */
void unlink_bundle(void);

/*
    Adds non-predefined kernel probe to the list.
*/
extern int add_probe_to_list (unsigned long addr, kernel_probe_t ** pprobe);

/*
    Removes non-predefined kernel probe from the list.
*/
extern int remove_probe_from_list (unsigned long addr);

/*
    Searches non-predefined kernel probe in the list.
*/
extern kernel_probe_t *find_probe (unsigned long addr);

/*
    Copies event from user space to buffer and updates its pid/tid/cpu/time.
*/
extern int put_us_event (char *data, unsigned long len);

/*
    Sets event mask.
*/
extern int set_event_mask (int new_mask);

/*
    Gets event mask.
*/
extern int get_event_mask (int *mask);

/*
    Sets predefined user space probes info.
*/
extern int set_predef_uprobes (ioctl_predef_uprobes_info_t *data);
/*
    Gets predefined user space probes info length.
*/
extern int get_predef_uprobes_size(int *size);
/*
    Gets predefined user space probes info.
*/
extern int get_predef_uprobes(ioctl_predef_uprobes_info_t *data);


// internal bookkeeping of storage
extern char *p_buffer;

// list of selected non-predefined kernel probes
extern struct hlist_head kernel_probes;

// multiple handlers stuff
/*struct dbi_modules_handlers {
	struct list_head	modules_handlers;
	spinlock_t		lock;
};

struct dbi_modules_handlers_info {
	struct module		*dbi_module;
	struct handler_map	*dbi_handlers;
	int			dbi_nr_handlers;
	struct list_head	dbi_list_head;
};

extern int dbi_register_handlers_module(struct dbi_modules_handlers_info *dbi_mhi);
extern int dbi_unregister_handlers_module(struct dbi_modules_handlers_info *dbi_mhi);
//unsigned long get_dbi_modules_handlers(void);*/

/* list of on-the-go installed kernel probes */
extern struct hlist_head otg_kernel_probes;

extern struct list_head otg_us_proc_info;

// event mask
extern int event_mask;

// process pid to instrument
extern unsigned int inst_pid;

typedef struct
{
	char *name;
	int installed;
	struct jprobe jprobe;
	struct kretprobe retprobe;
	unsigned long offset;
} us_proc_ip_t;

typedef struct
{
	us_proc_ip_t ip;
	pid_t tgid;
	struct list_head list;
} us_proc_otg_ip_t;

typedef struct
{
	int installed;
	struct jprobe jprobe;
	unsigned long addr;
	struct list_head list;
} us_proc_vtp_t;

typedef struct
{
	//char *name;
	char type;
	unsigned long size;
	signed char reg;	// -1 - memory, 0..127 - register number
	long off;
	struct list_head list;
} us_proc_vtp_data_t;

typedef struct dentry *STRUCT_DENTRY_PTR;
typedef struct vfsmount *STRUCT_VFSMOUNT_PTR;

typedef struct
{
	char *path;
	char *path_dyn;
	STRUCT_DENTRY_PTR m_f_dentry;
	STRUCT_VFSMOUNT_PTR m_vfs_mount;
	unsigned ips_count;
	us_proc_ip_t *p_ips;
	unsigned vtps_count;
	us_proc_vtp_t *p_vtps;
	int loaded;
} us_proc_lib_t;


//#include "new_dpf.h"

typedef struct
{
	char *path;
	STRUCT_DENTRY_PTR m_f_dentry;
	pid_t tgid;
	unsigned unres_ips_count;
	unsigned unres_vtps_count;
	unsigned unres_otg_ips_count;
	//kprobe_opcode_t *mapped_codelets;
	unsigned libs_count;
	us_proc_lib_t *p_libs;
#ifdef __ANDROID
	unsigned long libdvm_start;
	unsigned long libdvm_end;
	us_proc_ip_t libdvm_entry_ip;
	us_proc_ip_t libdvm_return_ip;
#endif /* __ANDROID */

	// new_dpf
	struct proc_probes *pp;
} inst_us_proc_t;

typedef struct
{
	unsigned int addr;
	unsigned int inst_type;
	char *name;
	char *class_name;
	char *method_name;
	char *prototype;

}dex_proc_ip_t;

typedef struct
{
	char *path;
	unsigned ips_count;
	dex_proc_ip_t *p_ips;

}inst_dex_proc_t;


struct cond {
	/* cond data itself */
	struct event_tmpl tmpl;
	/* linked list */
	struct list_head list;
	/* has been applied (for start and stop conditions) */
	int applied;
};

extern struct cond cond_list;

/* macros for testing flags */
#define ET_FIELD_CLR(flags, field) (flags &= ~field)
#define ET_FIELD_SET(flags, field) (flags |= field)
#define ET_FIELD_ISSET(flags, field) ((flags & field) != 0)

extern inst_us_proc_t us_proc_info;
extern inst_dex_proc_t dex_proc_info;

#endif /* !defined(__STORAGE_H__) */
