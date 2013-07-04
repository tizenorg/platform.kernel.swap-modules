#ifndef _MSG_CMD_H
#define _MSG_CMD_H

struct msg_buf;

int msg_keep_alive(struct msg_buf *mb);
int msg_start(struct msg_buf *mb);
int msg_stop(struct msg_buf *mb);
int msg_config(struct msg_buf *mb);
int msg_swap_inst_add(struct msg_buf *mb);
int msg_swap_inst_remove(struct msg_buf *mb);

#endif /* _MSG_CMD_H */
