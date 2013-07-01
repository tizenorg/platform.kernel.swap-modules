#ifndef __MESSAGE_HANDLER_H__
#define __MESSAGE_HANDLER_H__

int message_start(void __user *message_ptr);
int message_stop(void);
int message_config(void __user *message_ptr);
int message_swap_inst_add(void __user *message_ptr);
int message_swap_inst_remove(void __user *message_ptr);

#endif /* __MESSAGE_HANDLER_H__ */
