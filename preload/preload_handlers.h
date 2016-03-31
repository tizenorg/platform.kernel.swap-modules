#ifndef __PRELOAD_HANDLERS_H__
#define __PRELOAD_HANDLERS_H__

struct sspt_ip;
struct dentry;

int ph_uprobe_init(struct sspt_ip *ip);
void ph_uprobe_exit(struct sspt_ip *ip);

int ph_get_caller_init(struct sspt_ip *ip);
void ph_get_caller_exit(struct sspt_ip *ip);
int ph_get_call_type_init(struct sspt_ip *ip);
void ph_get_call_type_exit(struct sspt_ip *ip);
int ph_write_msg_init(struct sspt_ip *ip);
void ph_write_msg_exit(struct sspt_ip *ip);
void ph_set_handler_dentry(struct dentry *dentry);

#endif /* __PRELOAD_HANDLERS_H__ */
