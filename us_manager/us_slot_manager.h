#ifndef _US_SLOT_MANAGER_H
#define _US_SLOT_MANAGER_H

struct task_struct;
struct slot_manager;

struct slot_manager *create_sm_us(struct task_struct *task);
void free_sm_us(struct slot_manager *sm);

#endif /* _US_SLOT_MANAGER_H */
