#include <linux/kernel.h>

#define print_debug(msg, args...) \
	printk(KERN_DEBUG "SWAP_SAMPLER DEBUG : " msg, ##args)
#define print_msg(msg, args...)   \
	printk(KERN_INFO "SWAP_SAMPLER : " msg, ##args)
#define print_warn(msg, args...)  \
	printk(KERN_WARNING "SWAP_SAMPLER WARNING : " msg, ##args)
#define print_err(msg, args...)   \
	printk(KERN_ERR "SWAP_SAMPLER ERROR : " msg, ##args)
#define print_crit(msg, args...)  \
	printk(KERN_CRIT "SWAP_SAMPLER CRITICAL : " msg, ##args)
