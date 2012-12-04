#include "module.h"
#include "probes.h"
#include "storage.h"

#include "../kprobe/dbi_kprobes_deps.h"

#include "../../../modules/driver/module_common.h"

int fp_kallsyms_lookup_name = 0;
module_param(fp_kallsyms_lookup_name, uint, 0);
MODULE_PARM_DESC(fp_kallsyms_lookup_name,
				 "address of 'kallsyms_lookup_name' function");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)
#define tcp_opt tcp_sock
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
#define kmem_cache_t struct kmem_cache
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
extern void swap_register_notify (struct notifier_block *nb);
extern void swap_unregister_notify (struct notifier_block *nb);
#endif

#include "../../symbol/android/demangle.h"
#include "index_tree.h"
#include <allocator.h>

struct rb_root class_tree = RB_ROOT;

#include "probe_code.inc"

static int start_stop_notify(struct notifier_block *self, unsigned long action, void *data)
{
	unsigned int i =0;
	struct rb_root* pClass = 0;
	struct rb_root* pMethod = 0;
	struct rb_root* pProto = 0;


	switch (action)
	{
		case EC_IOCTL_ATTACH:
			{
				// fill in search tree
				DPRINTF("Registering dex probes");

				for ( i = 0; i < dex_proc_info.ips_count; i++ )
				{
					pClass = dict_insert ( &class_tree, dex_proc_info.p_ips[i].class_name );
					pMethod = dict_insert ( pClass, dex_proc_info.p_ips[i].method_name );
					pProto = dict_insert ( pMethod, dex_proc_info.p_ips[i].prototype );

					DPRINTF( "Registered probe for %s::%s::%s", dex_proc_info.p_ips[i].class_name, dex_proc_info.p_ips[i].method_name, dex_proc_info.p_ips[i].prototype );
				}

				DPRINTF("DEX probes registered OK");

				DPRINTF("DEX probes selftest...");
				for ( i = 0; i < dex_proc_info.ips_count; i++ )
				{
					pClass = dict_search ( &class_tree, dex_proc_info.p_ips[i].class_name );
					if ( 0 == pClass )
					{
						DPRINTF("DEX probes selftest class %s not found", dex_proc_info.p_ips[i].class_name );
						DPRINTF("DEX probes selftest...FAILED");
						continue;
					}

					pMethod = dict_search ( pClass, dex_proc_info.p_ips[i].method_name );
					if ( 0 == pMethod )
					{
						DPRINTF("DEX probes selftest method %s not found", dex_proc_info.p_ips[i].method_name );
						DPRINTF("DEX probes selftest...FAILED");
						continue;
					}


					pProto = dict_search ( pMethod, dex_proc_info.p_ips[i].prototype );
					if ( 0 == pProto )
					{
						DPRINTF("DEX probes selftest proto %s not found", dex_proc_info.p_ips[i].prototype );
						DPRINTF("DEX probes selftest...FAILED");
						continue;
					}

					DPRINTF( "Dex probe for %s::%s::%s TEST OK", dex_proc_info.p_ips[i].class_name, dex_proc_info.p_ips[i].method_name, dex_proc_info.p_ips[i].prototype );
				}


				break;
			}
		case EC_IOCTL_STOP_AND_DETACH:
			{
				// reset search tree
				dict_empty_tree( &class_tree );
				DPRINTF("DEX probes reset OK");
				break;
			}
	}

}

static struct notifier_block swap_nb = {
	.notifier_call = start_stop_notify,
};


unsigned long find_jp_handler(unsigned long addr)
{
	int i;

	/* Possibly we can find less expensive way */
	for (i = 0; i < nr_handlers; i++) {
		if (handlers[i].func_addr == addr)
			return handlers[i].jp_handler_addr;
	}

	return 0;
}

unsigned long find_rp_handler(unsigned long addr)
{
	int i;

	/* Possibly we can find less expensive way */
	for (i = 0; i < nr_handlers; i++) {
		if (handlers[i].func_addr == addr)
			return handlers[i].rp_handler_addr;
	}

	return 0;
}

DECLARE_PER_CPU (us_proc_ip_t *, gpCurIp);
DECLARE_PER_CPU (struct pt_regs *, gpUserRegs);

extern void dbi_uprobe_return(void);

#include "dalvik_defs.h"


static inline int IsAndroidEvent ( Method *arg1 )
{
	const char* szMethodName = arg1->name;
	const char* szPrototype = arg1->shorty;
	const char* szClassName = arg1->clazz->descriptor;
	const char* szDexFile = arg1->clazz->sourceFile;
	struct rb_root* pClass = NULL;
	struct rb_root* pMethod = NULL;
	struct rb_root* pProto = NULL;

	if ( dict_is_empty ( &class_tree ) )
		return 1;

	pClass = dict_search ( &class_tree, szClassName );

	if ( 0 == pClass )
	{
		return 0;
	}

	pMethod = dict_search ( pClass, szMethodName );

	if ( 0 == pMethod )
	{
		return 0;
	}

	pProto = dict_search ( pMethod, szPrototype );

	if ( 0 == pProto )
	{
		return 0;
	}

	return 1;
}


#include "uprobe_code.inc"


static int __init handlers_init(void)
{
	dbi_install_user_handlers();


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
	swap_register_notify(&swap_nb);
#endif

	return 0;
}

static void __exit handlers_exit(void)
{

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
	swap_unregister_notify(&swap_nb);
#endif

	dbi_uninstall_user_handlers();
}

module_init(handlers_init);
module_exit(handlers_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SWAP Dalvik VM handlers module");
MODULE_AUTHOR("Leonid Astakhov <l.astakhov@samsung.com>");
