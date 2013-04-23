#include <linux/module.h>

static int __init init_ks_manager(void)
{
       return 0;
}

static void __exit exit_ks_manager(void)
{
}

module_init(init_ks_manager);
module_exit(exit_ks_manager);

MODULE_LICENSE ("GPL");
