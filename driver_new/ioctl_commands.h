/* SWAP Device ioctl commands */

#include <linux/ioctl.h>

#ifndef __SWAP_DRIVER_IOCTL_COMMANDS__
#define __SWAP_DRIVER_IOCTL_COMMANDS__

#define SWAP_DRIVER_IOC_MAGIC 0xAF

// TODO Think about magic num

struct buffer_initialize {
    size_t size;
    unsigned int count;
};

#define SWAP_DRIVER_BUFFER_INITIALIZE       _IOW(SWAP_DRIVER_IOC_MAGIC, 1, \
                                                 struct buffer_initialize *)
#define SWAP_DRIVER_BUFFER_UNINITIALIZE     _IO(SWAP_DRIVER_IOC_MAGIC, 2)
#define SWAP_DRIVER_NEXT_BUFFER_TO_READ     _IO(SWAP_DRIVER_IOC_MAGIC, 3)
#define SWAP_DRIVER_FLUSH_BUFFER            _IO(SWAP_DRIVER_IOC_MAGIC, 4)
#define SWAP_DRIVER_MSG_START               _IOW(SWAP_DRIVER_IOC_MAGIC, 5, \
                                                 void *)
#define SWAP_DRIVER_MSG_STOP                _IO(SWAP_DRIVER_IOC_MAGIC, 6)
#define SWAP_DRIVER_MSG_CONFIG              _IOW(SWAP_DRIVER_IOC_MAGIC, 7,\
                                                 void *)
#define SWAP_DRIVER_MSG_SWAP_INST_ADD       _IOW(SWAP_DRIVER_IOC_MAGIC, 8,\
                                                 void *)
#define SWAP_DRIVER_MSG_SWAP_INST_REMOVE    _IOW(SWAP_DRIVER_IOC_MAGIC, 9,\
                                                 void *)

#endif /* __SWAP_DRIVER_IOCTL_COMMANDS__ */
