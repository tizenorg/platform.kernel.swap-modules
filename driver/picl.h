////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           PICL.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       PICL.cpp
//      AUTHOR:         L.Komkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.02
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(PICL_h)
#define PICL_h

#ifdef SWAP_HOST
#include <sys/time.h> // struct timeval
#else // SWAP_TARGET
#ifdef __KERNEL__
#include <linux/time.h>		// struct timeval
#else
#include <sys/time.h> // struct timeval
#endif
#endif

#define MAX_ARGS_DATA 200

#define EVENT_MAX_SIZE 2048*5

/* EvenRecord format
 ______________________________________________________________________________________________________________
| Len | RecType | EventType | Time | Pid | Tid | CPU | ArgsCount |  ArgTypes  |    ArgValues       | PreEventLen |
 __4b_____4b________4b________8b_____4b____4b_____4b______4b________ArgCount___variable-length._______4b_____
  
*/

typedef enum
{
	RECORD_ENTRY = 0,
	RECORD_RET,
	RECORD_PROFILE,

	RECORD_TYPE_COUNT	// fictional record type used to count real record types
} record_type_t;

const char *ec_record_type_to_name (record_type_t record_type);
int ec_record_type_by_name (record_type_t * p_record_type, const char *record_type_name);

// old Picl.h

#define _TRACE_TYPE        0
#define _TRACE_STATS_TYPE  2

typedef union tagArgValueType
{
	char m_char;
	int m_int;
	long m_long;
	float m_float;
	double m_double;
	void *m_pointer;
	char *m_string;
} _ARG_VALUE_TYPE;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#include <stdint.h>
#endif

struct common_timeval {
	uint32_t tv_sec;
	uint32_t tv_usec;
};

typedef uint32_t TYPEOF_EVENT_LENGTH;
typedef uint32_t TYPEOF_EVENT_TYPE;
typedef uint32_t TYPEOF_PROBE_ID;
typedef struct common_timeval TYPEOF_TIME;
typedef uint32_t TYPEOF_PROCESS_ID;
typedef uint32_t TYPEOF_THREAD_ID;
typedef uint32_t TYPEOF_CPU_NUMBER;
typedef uint32_t TYPEOF_NUMBER_OF_ARGS;

typedef struct tagEventHeader
{
	TYPEOF_EVENT_LENGTH m_nLength;
	TYPEOF_EVENT_TYPE m_nType;
	TYPEOF_PROBE_ID m_nProbeID;
	TYPEOF_TIME m_time;
	TYPEOF_PROCESS_ID m_nProcessID;
	TYPEOF_THREAD_ID m_nThreadID;
	TYPEOF_CPU_NUMBER m_nCPU;
	TYPEOF_NUMBER_OF_ARGS m_nNumberOfArgs;
} SWAP_TYPE_EVENT_HEADER;

typedef struct tagEvent
{
	SWAP_TYPE_EVENT_HEADER *m_pHeader;
	char *m_pDescriptor;
	char *m_pData;
} SWAP_TYPE_EVENT;

/*
	Argument Descriptors

	c - char
	h - short
	d - int
	x - long
	p - pointer
	f - float
	w - double
	s - string
*/

typedef enum
{
	AT_UNKNOWN,
	AT_CHAR,
	AT_SHORT,
	AT_INT,
	AT_LONG,
	AT_PTR,
	AT_FLOAT,
	AT_DOUBLE,
	AT_STRING,
	AT_ARRAY
} TYPE_ARGUMENT;

#define ALIGN_VALUE(x) ((x) + (4 - ((x) % 4)))

#endif /* !defined(PICL_h) */
