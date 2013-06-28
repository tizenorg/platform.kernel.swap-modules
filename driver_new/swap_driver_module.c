#include <linux/module.h>

#include "driver_defs.h"
#include "device_driver.h"

int register_swap_message_parser_handler(void *s_m_p_h)
{
    return register_message_handler(s_m_p_h);
}
EXPORT_SYMBOL_GPL(register_swap_message_parser_handler);

static int __init swap_driver_init(void)
{
    print_msg("Module init\n");

#ifdef TEST_MODE
    print_msg("Test mode on\n");
#endif

    swap_device_init();

    return 0;
}

static void __exit swap_driver_exit(void)
{
    //TODO Kill userspace daemon process
    swap_device_exit();
    print_msg("Module exit\n");
}

module_init(swap_driver_init);
module_exit(swap_driver_exit);

MODULE_LICENSE("GPL");
