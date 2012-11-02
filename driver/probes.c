////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           probes.c
//
//      DESCRIPTION:
//      This file is C source for SWAP driver.
//
//      SEE ALSO:       probes.h
//      AUTHOR:         L.Komkov, S.Grekhov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include "module.h"
#include "probes.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)
#define tcp_opt tcp_sock
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#define kmem_cache_t struct kmem_cache
#endif

/*
#define UNUSED __attribute__((unused))

#define USER_PRIO(p)		((p)-MAX_RT_PRIO)
#define MAX_USER_PRIO		(USER_PRIO(MAX_PRIO))

#define PRIO_BONUS_RATIO	 25
#define MAX_BONUS		(MAX_USER_PRIO * PRIO_BONUS_RATIO / 100)
#define INTERACTIVE_DELTA	  2

#define PRIO_TO_NICE(prio)	((prio) - MAX_RT_PRIO - 20)
#define TASK_NICE(p)		PRIO_TO_NICE((p)->static_prio)

#define SCALE(v1,v1_max,v2_max) (v1) * (v2_max) / (v1_max)

#define DELTA(p) (SCALE(TASK_NICE(p), 40, MAX_BONUS) + INTERACTIVE_DELTA)

#define TASK_INTERACTIVE(p) ((p)->prio <= (p)->static_prio - DELTA(p))
*/

const char *ec_probe_name[] = {
	"ks_probe_id",
	"us_probe_id",
	"vtp_probe_id",
	"dyn_lib_probe_id",
	"plt_addr_probe_id",
	"event_fmt_probe_id",
	"rq_profile",
	"pid_rq_profile"
};

//TODO: the same function should be used from utils.cpp
int name2index (unsigned *p_index, unsigned count, const char **names, const char *name)
{
	unsigned index;
	for (index = 0; index < count; ++index) {
		if (!strcmp (names[index], name)) {
			*p_index = index;
			return 0;
		}
	}
	return -EINVAL;
}

