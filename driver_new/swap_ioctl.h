#ifndef __SWAP_IOCTL_H__
#define __SWAP_IOCTL_H__

#include <linux/ioctl.h>

#define SWAP_DRIVER_IOC_MAGIC 0xAF

/* TODO: Think about magic num */

struct buffer_initialize {
	size_t size;
	unsigned int count;
};

/* SWAP Device ioctl commands */

#define SWAP_DRIVER_BUFFER_INITIALIZE		_IOW(SWAP_DRIVER_IOC_MAGIC, 1, \
						     struct buffer_initialize *)
#define SWAP_DRIVER_BUFFER_UNINITIALIZE		_IO(SWAP_DRIVER_IOC_MAGIC, 2)
#define SWAP_DRIVER_NEXT_BUFFER_TO_READ		_IO(SWAP_DRIVER_IOC_MAGIC, 3)
#define SWAP_DRIVER_FLUSH_BUFFER		_IO(SWAP_DRIVER_IOC_MAGIC, 4)
#define SWAP_DRIVER_MSG				_IOW(SWAP_DRIVER_IOC_MAGIC, 5, \
						     void *)

#endif /* __SWAP_IOCTL_H__ */
