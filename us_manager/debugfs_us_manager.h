#ifndef __DEBUGFS_US_MANAGER_H__
#define __DEBUGFS_US_MANAGER_H__

#define US_MANAGER_DFS_DIR "us_manager"
#define US_MANAGER_TASKS   "tasks"

int init_debugfs_us_manager(void);
void exit_debugfs_us_manager(void);

#endif /* __DEBUGFS_US_MANAGER_H__ */
