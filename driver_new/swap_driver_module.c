#include <linux/module.h>

#include "driver_defs.h"
#include "device_driver.h"

static int __init swap_driver_init(void)
{
	swap_device_init();
    print_msg("Driver module initialized\n");

	return 0;
}

static void __exit swap_driver_exit(void)
{
	swap_device_exit();
    print_msg("Driver module uninitialized\n");
}

module_init(swap_driver_init);
module_exit(swap_driver_exit);

MODULE_LICENSE("GPL");
