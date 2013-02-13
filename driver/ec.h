////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           ec.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       ec.c
//      AUTHOR:         L.Komkov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(__EC_H__)
#define __EC_H__

#include "ec_ioctl.h"
#include "ec_info.h"
#include "ec_probe.h"
#include "picl.h"
#include "stdswap_defs.h"

extern ec_info_t ec_info;
extern ec_probe_info_t ec_probe_info;
extern spinlock_t ec_spinlock;

extern int ec_user_attach (void);
extern int ec_user_activate (void);
extern int ec_user_stop (void);
extern int ec_kernel_activate (void);
extern int ec_kernel_stop (void);

extern int copy_ec_info_to_user_space (ec_info_t * p_user_ec_info);
extern ec_state_t GetECState(void);
extern void reset_ec_info_nolock(void);
extern void ResetECInfo(void);
extern void CleanECInfo(void);
extern int IsECMode(unsigned long nMask);
extern int IsContinuousRetrieval(void);
extern int SetECMode(unsigned long nECMode);
extern unsigned long GetECMode(void);
extern int is_java_inst_enabled(void);
extern struct timeval last_attach_time;
extern int paused;

#endif /* !defined(__EC_H__) */
