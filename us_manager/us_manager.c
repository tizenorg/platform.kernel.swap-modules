#include <linux/module.h>

static int __init init_us_manager(void)
{
	return 0;
}

static void __exit exit_us_manager(void)
{
}

module_init(init_us_manager);
module_exit(exit_us_manager);

MODULE_LICENSE ("GPL");

