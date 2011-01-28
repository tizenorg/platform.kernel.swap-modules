////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           module.c
//
//      DESCRIPTION:
//      This file is C source for SWAP driver.
//
//      SEE ALSO:       module.h
//      AUTHOR:         L.Komkov, A.Gerenkov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group 
//      CREATED:        2008.02.15
//      VERSION:        1.0
//      REVISION DATE:  2008.12.03
//
////////////////////////////////////////////////////////////////////////////////////

#include "module.h"

int fp_kallsyms_lookup_name = 0;
module_param (fp_kallsyms_lookup_name, int, 0);
MODULE_PARM_DESC (fp_kallsyms_lookup_name, "address of 'kallsyms_lookup_name' function");

char gl_szDefaultDeviceName[128] = DEFAULT_DEVICE_NAME;
char* device_name = NULL;
module_param (device_name, charp, 0);
MODULE_PARM_DESC (device_name, "device name for '/proc/devices'");

unsigned int device_major = 0;
module_param (device_major, uint, 0);
MODULE_PARM_DESC (device_major, "default device major number");

fp_kallsyms_lookup_name_t lookup_name;

#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
void (*__real_put_task_struct) (struct task_struct * tsk);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11))
#define SWAPDRV_PUT_TASK_STRUCT	"put_task_struct"
void
put_task_struct (struct task_struct *tsk)
{
	__real_put_task_struct (tsk);
}
#else
#define SWAPDRV_PUT_TASK_STRUCT	"__put_task_struct"
void
__put_task_struct (struct task_struct *tsk)
{
	__real_put_task_struct (tsk);
}
#endif
#else /*2.6.16 */
void (*__real_put_task_struct) (struct rcu_head * rhp);
#define SWAPDRV_PUT_TASK_STRUCT	"__put_task_struct_cb"
void
__put_task_struct_cb (struct rcu_head *rhp)
{
	__real_put_task_struct (rhp);
}
#endif
/*void (*__real_put_task_struct)(struct task_struct *tsk);
void __put_task_struct(struct task_struct *tsk)
{
	__real_put_task_struct(tsk);
}*/

#if defined(CONFIG_MIPS)
void (*flush_cache_page) (struct vm_area_struct * vma, unsigned long page);
#endif

static int __init InitializeModule(void)
{
	if(!fp_kallsyms_lookup_name) {
		EPRINTF("fp_kallsyms_lookup_name parameter undefined!");
		return -1;
	}
	if(device_name == NULL) {
		EPRINTF("Using default device name!");
		device_name = gl_szDefaultDeviceName;
	}
	if(device_major == 0) {
		EPRINTF("Using default device major number!");
		device_major = DEFAULT_DEVICE_MAJOR;
	}

	lookup_name = (fp_kallsyms_lookup_name_t) fp_kallsyms_lookup_name;
	__real_put_task_struct = (void *) lookup_name (SWAPDRV_PUT_TASK_STRUCT);
	if (!__real_put_task_struct)
	{
		EPRINTF (SWAPDRV_PUT_TASK_STRUCT " is not found! Oops. Where is it?");
		return -ESRCH;
	}

#if defined(CONFIG_MIPS)
	flush_cache_page = (void *) lookup_name ("r4k_flush_cache_page");
	if (!flush_cache_page)
	{
		EPRINTF ("failed to resolve 'flush_cache_page'!\n");
		return -ESRCH;
	}
#endif

	if(probes_manager_init() < 0) {
		EPRINTF ("Cannot initialize probe manager!");
		return -1;
	}
	if(device_init() < 0) {
		EPRINTF ("Cannot initialize device!");
		return -1;
	}

	INIT_LIST_HEAD(&cond_list.list);

	DPRINTF ("is successfully initialized.");
	return 0;
}

static void __exit UninitializeModule (void)
{
	ec_user_stop ();
	device_down ();
	probes_manager_down ();
	DPRINTF ("is successfully finished.");
}

module_init (InitializeModule);
module_exit (UninitializeModule);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR("Adwanced Software Group (SRC, Moscow)");
MODULE_DESCRIPTION("InPerfA Device Driver");
MODULE_VERSION("4:1.0");
