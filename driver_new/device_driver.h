#ifndef __SWAP_DRIVER_DEVICE_DRIVER__
#define __SWAP_DRIVER_DEVICE_DRIVER__

/* Create and register device */
int swap_device_init(void);

/* Delete device */
void swap_device_exit(void);

/* Register swap_message_parser handler */
int register_message_handler(void *s_m_p_h);

#endif /* __SWAP_DRIVER_DEVICE_DRIVER__ */
