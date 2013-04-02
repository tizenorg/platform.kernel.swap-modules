#define MAX_ERROR_BUF_PATH 256
#define IS_APP  0
#define IS_LIB  1

// copy error buffer from kernelspace to userspace
int get_last_error(void* u_addr);
int has_last_error(void);
int update_errno_buffer(char *buffer, const unsigned int type);
