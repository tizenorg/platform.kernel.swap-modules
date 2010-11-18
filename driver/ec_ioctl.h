////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           ec_module.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       N/A
//      AUTHOR:         L.Komkov, S.Dianov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.02
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(ec_ioctl_h)
#define ec_ioctl_h

#include "ec_info.h"		// ec_info_t
#include "picl.h"

typedef enum
{
	// modes
	EC_IOCTL_SET_EC_MODE,
	EC_IOCTL_GET_EC_MODE,

	// buffer manipulation
	EC_IOCTL_SET_BUFFER_SIZE,
	EC_IOCTL_GET_BUFFER_SIZE,
	EC_IOCTL_RESET_BUFFER,

	// probes management
	EC_IOCTL_SELECT_PROBE,
	EC_IOCTL_DESELECT_PROBE,
	EC_IOCTL_GET_PROBE_INFO,
	EC_IOCTL_ADD_PROBE,
	EC_IOCTL_SET_APPDEPS,
	EC_IOCTL_SET_PROFILEBUNDLE,
	//EC_IOCTL_REMOVE_PROBE,
	EC_IOCTL_RESET_PROBES,
	EC_IOCTL_SET_COMPLEX_PROBES,

	// tracing
	EC_IOCTL_ATTACH,	// attaches selected probes
	EC_IOCTL_ACTIVATE,	// START

	// stop is common for both tracing and profiling
	EC_IOCTL_STOP_AND_DETACH,	// STOP (and detach for TRACING)

	// kernel to user notification delivery
	EC_IOCTL_WAIT_NOTIFICATION,

	// get ec_info
	EC_IOCTL_GET_EC_INFO,
	EC_IOCTL_GET_COMPLEX_STATUS,
	EC_IOCTL_CONSUME_BUFFER,

	// instrument user space process
	EC_IOCTL_INST_USR_SPACE_PROC,
	// deinstrument user space process
	EC_IOCTL_DEINST_USR_SPACE_PROC,

	// conditions
	EC_IOCTL_UPDATE_CONDS,

	//user space event	
	EC_IOCTL_US_EVENT,

	//event format
	EC_IOCTL_SET_EVENT_MASK,
	EC_IOCTL_GET_EVENT_MASK,

	// pre-defined user space probes
	EC_IOCTL_SET_PREDEF_UPROBES,	
	EC_IOCTL_GET_PREDEF_UPROBES,
	EC_IOCTL_GET_PREDEF_UPROBES_SIZE,

} EC_IOCTL_CMD;

typedef struct
{
	unsigned notification_count;
	ec_info_t *p_ec_info;
} ioctl_wait_notification_t;

typedef struct
{
	int m_signedInt;
	unsigned int m_unsignedInt;
	long m_signedLong;
	unsigned long m_unsignedLong;
	char* m_ptrChar;
} ioctl_general_t;

typedef enum
{
	OPERATION_ANY,		// means do not check value
	OPERATION_EQUAL,
	OPERATION_NOT_EQUAL,
	OPERATION_LESS,
	OPERATION_GREATER
} operation_t;

typedef struct
{
	unsigned m_condition_always_false;
	unsigned m_op_time;
	unsigned m_op_pid;
	unsigned m_op_tid;
	unsigned m_op_probe_id;
//      char     m_probe_name[SWAP_COMMON_STRING_SIZE];
	unsigned m_op_record_type;
	unsigned m_time_sec;
	unsigned m_time_usec;
	unsigned m_pid;
	unsigned m_tid;
	unsigned m_probe_id;
	unsigned m_record_type;
} condition_t;



// condition matching any event
#define CONDITION_ANY \
{ \
    .m_condition_always_false = 0, \
        .m_op_time = OPERATION_ANY, \
        .m_op_pid = OPERATION_ANY, \
        .m_op_tid = OPERATION_ANY, \
        .m_op_probe_id = OPERATION_ANY, \
        .m_op_record_type = OPERATION_ANY, \
} \

// never matching condition
#define CONDITION_FALSE \
{ \
    .m_condition_always_false = 1, \
        .m_op_time = OPERATION_ANY, \
        .m_op_pid = OPERATION_ANY, \
        .m_op_tid = OPERATION_ANY, \
        .m_op_probe_id = OPERATION_ANY, \
        .m_op_record_type = OPERATION_ANY, \
} \

// default start condition - start immediately
#define DEFAULT_START_CONDITION CONDITION_ANY
// default stop condition - never stop
#define DEFAULT_STOP_CONDITION CONDITION_FALSE


typedef struct
{
	unsigned count;
	int *p_pids;
} ioctl_set_pids_to_ignore_t;


typedef struct
{
	char *name;
	unsigned long addr;
	char type;
	unsigned long size;
	signed char reg;	// -1 - memory, 0..127 - register number  
	long off;
} ioctl_usr_space_vtp_t;

typedef struct
{
	//char *name;
	//unsigned name_len;
	unsigned long addr;
} ioctl_usr_space_ip_t;

typedef struct
{
	char *path;
	//unsigned path_len;
	unsigned ips_count;
	ioctl_usr_space_ip_t *p_ips;
	unsigned vtps_count;
	ioctl_usr_space_vtp_t *p_vtps;
} ioctl_usr_space_lib_t;

typedef struct
{
	char *path;
	//unsigned path_len;
	unsigned libs_count;
	ioctl_usr_space_lib_t *p_libs;
} ioctl_inst_usr_space_proc_t;

typedef struct
{
	char *proc_name;
	unsigned count;
} ioctl_set_proc_to_ignore_t;

typedef struct
{
	char *data;
	unsigned len;
} ioctl_us_event_t;
 
// exclude entry events
#define IOCTL_EMASK_ENTRY	0x01
// exclude exit events
#define IOCTL_EMASK_EXIT 	0x02
// timestamp
#define IOCTL_EMASK_TIME 	0x04
// PID
#define IOCTL_EMASK_PID		0x08
// TID
#define IOCTL_EMASK_TID 	0x10
// CPU
#define IOCTL_EMASK_CPU 	0x20
// Args
#define IOCTL_EMASK_ARGS 	0x40

typedef struct
{
	unsigned probes_count;
	char *p_probes;
} ioctl_predef_uprobes_info_t;


#endif /* !defined(ec_ioctl_h) */
