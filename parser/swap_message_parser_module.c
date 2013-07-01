#include <linux/module.h>

#include "parser_defs.h"
#include "message_handler.h"
#include "swap_message_parser_errors.h"

#include "/home/alexander/swap_driver/swap_driver_module.h" //TODO Remove hardcode
#include "/home/alexander/swap_driver/ioctl_commands.h" // TODO Remove hardcode


int swap_message_parser_handler(unsigned int cmd, void __user *msg)
{
    int result;

    switch(cmd) {
        case SWAP_DRIVER_MSG_START:
        {
            result = message_start(msg);
            break;
        }
        case SWAP_DRIVER_MSG_STOP:
        {
            result = message_stop();
            break;
        }
        case SWAP_DRIVER_MSG_CONFIG:
        {
            result = message_config(msg);
            break;
        }
        case SWAP_DRIVER_MSG_SWAP_INST_ADD:
        {
            result = message_swap_inst_add(msg);
            break;
        }
        case SWAP_DRIVER_MSG_SWAP_INST_REMOVE:
        {
            result = message_swap_inst_remove(msg);
            break;
        }
        default:
        {
            result = -E_SMP_UNKNOWN_MESSAGE;
            break;
        }
    }

    return result;
}

static int register_swap_message_parser(void)
{
    int result;

    result = register_swap_message_parser_handler(swap_message_parser_handler);

    return result;
}


static int __init swap_message_parser_init(void)
{
    int result;

    result = register_swap_message_parser();
    if (result != 0) {
        print_err("SWAP Message Parser handler was not registered! Message parser won't work!\n");
        return result;
    }

    print_msg("Module init\n");

    return result;
}

static void __exit swap_message_parser_exit(void)
{
    print_msg("Module exit\n");
}

module_init(swap_message_parser_init);
module_exit(swap_message_parser_exit);

MODULE_LICENSE("GPL");
