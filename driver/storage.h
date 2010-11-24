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

/*
    Function "set_us_proc_inst()" saves instrumentation info for user space process.
*/
extern int set_us_proc_inst_info (ioctl_inst_usr_space_proc_t * inst_info);

/* Set most links from us_proc_info to data in the bundle */
int link_bundle();

/* Undo the actions of link_bundle() */
void unlink_bundle();

/*
    Function "release_us_proc_inst_info()" destroys instrumentation info for user space process.
*/
extern void release_us_proc_inst_info (void);

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

// event mask
extern int event_mask;

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

typedef struct
{
	char *path;
	STRUCT_DENTRY_PTR m_f_dentry;
	unsigned ips_count;
	us_proc_ip_t *p_ips;
	unsigned vtps_count;
	us_proc_vtp_t *p_vtps;
	int loaded;
} us_proc_lib_t;

typedef struct
{
	char *path;
	STRUCT_DENTRY_PTR m_f_dentry;
	pid_t tgid;
	unsigned unres_ips_count;
	unsigned unres_vtps_count;
	//kprobe_opcode_t *mapped_codelets;
	unsigned libs_count;
	us_proc_lib_t *p_libs;
} inst_us_proc_t;

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


#endif /* !defined(__STORAGE_H__) */
