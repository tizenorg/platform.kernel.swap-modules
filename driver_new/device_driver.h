#ifndef __SWAP_DRIVER_DEVICE_DRIVER__
#define __SWAP_DRIVER_DEVICE_DRIVER__

typedef int (*msg_handler_t)(void __user *data);

/* Set the message handler */
void set_msg_handler(msg_handler_t mh);

#endif /* __SWAP_DRIVER_DEVICE_DRIVER__ */
