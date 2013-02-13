#ifndef EVENTS_H_
#define EVENTS_H_

#define UNUSED __attribute__((unused))

#ifdef __KERNEL__
#include <asm/uaccess.h>	// copy_from_user
#include "debug.h"		// //DPRINTF
#else
#include <string.h>
#include <stdarg.h>
#endif
#include "picl.h"
#include "ec_ioctl.h"
#include "ec_probe.h"

static TYPE_ARGUMENT GetArgumentType (char ch)
{
	switch (ch)
	{
	case 'c':
		return AT_CHAR;
		break;
	case 'h':
		return AT_SHORT;
		break;
	case 'd':
		return AT_INT;
		break;
	case 'x':
		return AT_LONG;
		break;
	case 'p':
		return AT_PTR;
		break;
	case 'f':
		return AT_FLOAT;
		break;
	case 'w':
		return AT_DOUBLE;
		break;
	case 's':
		return AT_STRING;
		break;
	case 'a':
		return AT_ARRAY;
		break;
	};
	return AT_UNKNOWN;
}

static char *PackArguments (char *pBuffer, unsigned long nLen, const char *szFormat, va_list args)
{
	TYPE_ARGUMENT nArgType = AT_UNKNOWN;
	const char *pChar = NULL;
	char chCode = '\0';
	char *pResult = pBuffer;
	unsigned long nLengthOfDescriptor = 0, nFree = nLen;
	unsigned long nSizeOfDescriptor = 0;

	// Descriptor
	nLengthOfDescriptor = strlen (szFormat) + 1;
	nSizeOfDescriptor = ALIGN_VALUE(nLengthOfDescriptor);
	if(nFree < nSizeOfDescriptor)
		return NULL; // no space for descriptor
	memcpy (pResult, szFormat, nLengthOfDescriptor);
	pResult += nSizeOfDescriptor;
	nFree -= nSizeOfDescriptor;

	for (pChar = szFormat; (chCode = *pChar) != '\0'; pChar++)
	{
		nArgType = GetArgumentType(chCode);
		switch (nArgType)
		{
		case AT_CHAR:
			{
				int ch = va_arg (args, int);
				if(nFree < sizeof(ch))
					return NULL; // no space for arg
				memcpy(pResult, &ch, sizeof (ch));
				pResult += sizeof (ch);
				nFree -= sizeof (ch);
			}
			break;
		case AT_SHORT:
			{
				int nShort = va_arg (args, int);
				if(nFree < sizeof(nShort))
					return NULL; // no space for arg
				memcpy(pResult, &nShort, sizeof (nShort));
				pResult += sizeof (nShort);
				nFree -= sizeof (nShort);
			}
			break;
		case AT_INT:
			{
				int nInt = va_arg (args, int);
				if(nFree < sizeof(nInt))
					return NULL; // no space for arg
				memcpy(pResult, &nInt, sizeof (nInt));
				pResult += sizeof (nInt);
				nFree -= sizeof (nInt);
			}
			break;
		case AT_LONG:
			{
				long nLong = va_arg (args, long);
				if(nFree < sizeof(nLong))
					return NULL; // no space for arg
				memcpy (pResult, &nLong, sizeof (nLong));
				pResult += sizeof (nLong);
				nFree -= sizeof (nLong);
			}
			break;
		case AT_PTR:
			{
				void *p = va_arg (args, void *);
				if(nFree < sizeof(p))
					return NULL; // no space for arg
				memcpy (pResult, &p, sizeof (p));
				pResult += sizeof (p);
				nFree -= sizeof (p);
			}
			break;
		case AT_FLOAT:
			{
				double fValue = va_arg (args, double);
				if(nFree < sizeof(fValue))
					return NULL; // no space for arg
				memcpy (pResult, &fValue, sizeof (fValue));
				pResult += sizeof (fValue);
				nFree -= sizeof (fValue);
			}
			break;
		case AT_DOUBLE:
			{
				double fDouble = va_arg (args, double);
				if(nFree < sizeof(fDouble))
					return NULL; // no space for arg
				memcpy (pResult, &fDouble, sizeof (fDouble));
				pResult += sizeof (fDouble);
				nFree -= sizeof (fDouble);
			}
			break;
		case AT_STRING:
		{
			const char *s = va_arg (args, const char *);
			int nLengthOfString = 0, nSizeOfString;
			if(!s) {
				/* If string poiner is NULL then */
				s = "(null)";
			}
#ifdef __KERNEL__
			if((void *)s < (void *)TASK_SIZE) {
				const char __user *user_s = (const char __user *)s;
				nLengthOfString = strlen_user(user_s);
				if(nFree < nLengthOfString)
					return NULL; // no space for arg
				if(strncpy_from_user(pResult,
						     user_s,
						     nLengthOfString) != (nLengthOfString-1)) {
					EPRINTF("failed to copy string from user %p, bytes %d",
						user_s, nLengthOfString);
				}
			}
			else
#endif
			{
				nLengthOfString = strlen (s) + 1;
				if(nFree < nLengthOfString)
					return NULL; // no space for arg
				memcpy (pResult, s, nLengthOfString);
			}
			nSizeOfString = ALIGN_VALUE (nLengthOfString);
			if(nFree < nSizeOfString)
				return NULL; // no space for arg
			pResult += nSizeOfString;
			nFree -= nSizeOfString;
		}
		break;
		case AT_ARRAY:
			{
				int nLength = va_arg (args, int);
				void *p = NULL;
				int nSize = 0;
				nSize = ALIGN_VALUE (nLength);
				if(nFree < nSize)
					return NULL; // no space for arg
				memcpy (pResult, &nLength, sizeof (int));
				pResult += sizeof (int);
				p = va_arg (args, void *);
#ifdef __KERNEL__
				if((void *)p < (void *)TASK_SIZE) {
					const void __user *P = (void __user *) va_arg(args, void*);
					if(copy_from_user(pResult, P, nLength)!= 0)
						EPRINTF ("failed to copy array from user %p, bytes %d", P, nLength);
				}
				else
#endif
					memcpy (pResult, p, nLength);
				pResult += nSize;
				nFree -= nSize;
			}
			break;
		default:
			break;
		};
	}
	return pResult;
}

static UNUSED TYPEOF_EVENT_LENGTH VPackEvent(char *buf, unsigned long buf_len, int mask, TYPEOF_PROBE_ID probe_id,
				TYPEOF_EVENT_TYPE record_type, TYPEOF_TIME *tv, TYPEOF_PROCESS_ID pid,
				TYPEOF_THREAD_ID tid, TYPEOF_CPU_NUMBER cpu, const char *fmt, va_list args)
{
	char *cur = buf;
	SWAP_TYPE_EVENT_HEADER *pEventHeader = (SWAP_TYPE_EVENT_HEADER *)buf;

	if(buf_len < sizeof(SWAP_TYPE_EVENT_HEADER))
		return 0; // no space for header

	pEventHeader->m_nLength = 0;
	cur += sizeof(TYPEOF_EVENT_LENGTH);
	pEventHeader->m_nType = record_type;
	cur += sizeof(TYPEOF_EVENT_TYPE);
	pEventHeader->m_nProbeID = probe_id;
	cur += sizeof(TYPEOF_PROBE_ID);
	//pEventHeader->m_time.tv_sec = tv->tv_sec;
	//pEventHeader->m_time.tv_usec = tv->tv_usec;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(mask & IOCTL_EMASK_TIME)){
		memcpy(cur, tv, sizeof(TYPEOF_TIME));
		cur += sizeof(TYPEOF_TIME);
	}
	//pEventHeader->m_nProcessID = pid;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(mask & IOCTL_EMASK_PID)){
		(*(TYPEOF_PROCESS_ID *)cur) = pid;
		cur += sizeof(TYPEOF_PROCESS_ID);
	}
	//pEventHeader->m_nThreadID = tid;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(mask & IOCTL_EMASK_TID)){
		(*(TYPEOF_THREAD_ID *)cur) = tid;
		cur += sizeof(TYPEOF_THREAD_ID);
	}
	//pEventHeader->m_nCPU = cpu;
	if((probe_id == EVENT_FMT_PROBE_ID) || !(mask & IOCTL_EMASK_CPU)){
		(*(TYPEOF_CPU_NUMBER *)cur) = cpu;
		cur += sizeof(TYPEOF_CPU_NUMBER);
	}
	// dyn lib event should have all args, it is for internal use and not visible to user
	if((probe_id == EVENT_FMT_PROBE_ID) || (probe_id == DYN_LIB_PROBE_ID) || !(mask & IOCTL_EMASK_ARGS)){
		(*(TYPEOF_NUMBER_OF_ARGS *)cur) = strlen(fmt);
		cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
		cur = PackArguments(cur, buf_len-(cur-buf), fmt, args);
		if(!cur) return 0; // no space for args
	}
	else {
		// user space and dynamic kernel probes should have at least one argument
		// to identify them
		if((probe_id == US_PROBE_ID) || (probe_id == VTP_PROBE_ID) || (probe_id == KS_PROBE_ID)){
			char fmt2[2];
			(*(TYPEOF_NUMBER_OF_ARGS *)cur) = 1;
			cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
			// pack args using format string for the 1st arg only
			fmt2[0] = fmt[0]; fmt2[1] = '\0';
			cur = PackArguments(cur, buf_len-(cur-buf), fmt2, args);
			if(!cur) return 0; // no space for args
		}
		else {
			(*(TYPEOF_NUMBER_OF_ARGS *)cur) = 0;
			cur += sizeof(TYPEOF_NUMBER_OF_ARGS);
		}
	}

	pEventHeader->m_nLength = cur - buf + sizeof(TYPEOF_EVENT_LENGTH);
	if(buf_len < pEventHeader->m_nLength)
		return 0;// no space for back length
	//memcpy(cur, &pEventHeader->m_nLength, sizeof(TYPEOF_EVENT_LENGTH));
	*((TYPEOF_EVENT_LENGTH *)cur) = pEventHeader->m_nLength;

	return pEventHeader->m_nLength;
}

/*static TYPEOF_EVENT_LENGTH PackEvent(char *buf, unsigned long buf_len, TYPEOF_PROBE_ID probe_id,
				TYPEOF_EVENT_TYPE record_type, TYPEOF_TIME *tv, TYPEOF_PROCESS_ID pid,
				TYPEOF_THREAD_ID tid, TYPEOF_CPU_NUMBER cpu, const char *fmt, ...)
{
	va_list args;
	TYPEOF_EVENT_LENGTH len;

	va_start (args, fmt);
	len = VPackEvent(buf, buf_len, probe_id, record_type, tv, pid, tid, cpu, fmt, args);
	va_end (args);

	return len;
}*/

#endif /*EVENTS_H_*/
