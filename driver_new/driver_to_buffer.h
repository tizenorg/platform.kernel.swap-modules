#ifndef __SWAP_DRIVER_DRIVER_TO_BUFFER__
#define __SWAP_DRIVER_DRIVER_TO_BUFFER__

int driver_to_buffer_initialize(size_t size, unsigned int count);
int driver_to_buffer_uninitialize(void);
ssize_t driver_to_buffer_write(size_t size, void* data);
ssize_t driver_to_buffer_read(char __user *buf, size_t count);
void driver_to_buffer_callback(void);
int driver_to_buffer_fill_spd(struct splice_pipe_desc *spd);
int driver_to_buffer_buffer_to_read(void);
int driver_to_buffer_next_buffer_to_read(void);
int driver_to_buffer_flush(void);


#endif /* __SWAP_DRIVER_DRIVER_TO_BUFFER__ */
