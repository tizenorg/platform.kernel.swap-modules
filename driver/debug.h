////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           debug.h
//
//      DESCRIPTION:
//	Debug functions for application
//	
//      SEE ALSO:       N/A
//      AUTHOR:         L.Komkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.02
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(__DEBUG_H__)
#define __DEBUG_H__

#include <linux/kernel.h>
#include <linux/string.h>	// strrchr

// #undef __DEBUG

#ifdef __DEBUG
#define DPRINTF(format, args...) do { \
	char *f = __FILE__; \
	char *n = strrchr(f, '/'); \
	printk("DRIVER[%s:%u:%s] DEBUG: " format "\n" , (n) ? n+1 : f, __LINE__, __FUNCTION__, ##args); \
    } while(0)
#else
#define DPRINTF(format, args...)
#endif

#define EPRINTF(format, args...) do { \
	char *f = __FILE__; \
	char *n = strrchr(f, '/'); \
	printk("DRIVER[%s:%u:%s] ERROR: " format "\n" , (n) ? n+1 : f, __LINE__, __FUNCTION__, ##args); \
    } while(0)


#endif /* !defined(__DEBUG_H__) */
