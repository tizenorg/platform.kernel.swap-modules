////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           device_driver.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       device_driver.c
//      AUTHOR:         L.Komkov, S.Dianov, S.Grekhov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(device_driver_h)
#define device_driver_h

#include "ec_info.h"		// ec_info_t
#include "ec_probe.h"		// probe_id_t

#define DEFAULT_DEVICE_NAME "inperfa_drv"
#define DEFAULT_DEVICE_MAJOR 250
#define EVENTS_AGGREGATION_USEC (5 * 1000000UL)

extern int device_init (void);
extern void device_down (void);
extern void notify_user (event_id_t event_id);

#endif /* !defined(device_driver_h) */
