#ifndef __SWAP_DRIVER_DEVICE_DEFS_H__
#define __SWAP_DRIVER_DEVICE_DEFS_H__

#include <linux/kernel.h>

#define print_debug(msg, args...) \
    printk(KERN_DEBUG "SWAP_DRIVER DEBUG : " msg, ##args)
#define print_msg(msg, args...)   \
    printk(KERN_INFO "SWAP_DRIVER : " msg, ##args)
#define print_warn(msg, args...)  \
    printk(KERN_WARNING "SWAP_DRIVER WARNING : " msg, ##args)
#define print_err(msg, args...)   \
    printk(KERN_ERR "SWAP_DRIVER ERROR : " msg, ##args)
#define print_crit(msg, args...)  \
    printk(KERN_CRIT "SWAP_DRIVER CRITICAL : " msg, ##args)

#endif /* __SWAP_DRIVER_DEVICE_DEFS_H__ */
