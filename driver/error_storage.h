#define MAX_ERROR_BUF_PATH 256

// copy error buffer from kernelspace to userspace
int get_last_error(void* u_addr);
int has_last_error(void);
int update_errno_buffer(const char *buffer);
void last_error_buffer_initialize(void);
