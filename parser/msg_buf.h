#ifndef _MSG_BUF_H
#define _MSG_BUF_H

#include <linux/types.h>

struct msg_buf {
	char *begin;
	char *end;
	char *ptr;
};

int init_mb(struct msg_buf *mb, size_t size);
void uninit_mb(struct msg_buf *mb);

int cmp_mb(struct msg_buf *mb, size_t size);
size_t remained_mb(struct msg_buf *mb);
int is_end_mb(struct msg_buf *mb);

int get_u32(struct msg_buf *mb, u32 *val);
int get_u64(struct msg_buf *mb, u64 *val);

int get_string(struct msg_buf *mb, char **str);
void put_string(char *str);

#endif /* _MSG_BUF_H */
