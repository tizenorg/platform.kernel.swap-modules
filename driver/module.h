////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           module.h
//
//      DESCRIPTION:
//
//      SEE ALSO:       module.c
//      AUTHOR:         L.Komkov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#if !defined(__MODULE_H__)
#define __MODULE_H__

#define UNUSED __attribute__((unused))

#include <linux/types.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <asm/local.h>
#include <asm/string.h>
#include <asm/mman.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_common.h>

#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/file.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ipsec.h>
#include <linux/sysctl.h>
#include <linux/dcache.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/audit.h>
#include <linux/namei.h>
#include <linux/signal.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/jiffies.h>
#include <linux/time.h>

#include "events.h"

#include "debug.h"
#include "ec.h"
#include "legacy.h"
#include "storage.h"
#include "us_proc_inst.h"
#include "device_driver.h"
#include "probes_manager.h"
#include "probes.h"
#include "../../tools/gpmu/probes/entry_data.h"

extern char *device_name;
extern unsigned int device_major;
extern storage_arg_t sa_dpf;

struct handler_map {
	unsigned long func_addr;
	unsigned long jp_handler_addr;
	unsigned long rp_handler_addr;
	char * func_name;
};

#endif /* !defined(module_h) */
