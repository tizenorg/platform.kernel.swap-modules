#ifndef _FEATURES_DATA_H
#define _FEATURES_DATA_H

#include <linux/types.h>

#define SYSCALL_LIST \
	X(sys_accept4), \
	X(sys_accept), \
	X(sys_access), \
	X(sys_acct), \
	X(sys_bind), \
	X(sys_chdir), \
	X(sys_chmod), \
	X(sys_chown16), \
	X(sys_chown), \
	X(sys_chroot), \
	X(sys_clone), \
	X(sys_connect), \
	X(sys_creat), \
	X(sys_dup3), \
	X(sys_epoll_create1), \
	X(sys_epoll_ctl), \
	X(sys_epoll_pwait), \
	X(sys_epoll_wait), \
	X(sys_eventfd2), \
	X(sys_eventfd), \
	X(sys_execve), \
	X(sys_exit_group), \
	X(sys_exit), \
	X(sys_faccessat), \
	X(sys_fadvise64_64), \
	X(sys_fallocate), \
	X(sys_fanotify_init), \
	X(sys_fanotify_mark), \
	X(sys_fchmodat), \
	X(sys_fchownat), \
	X(sys_fgetxattr), \
	X(sys_flistxattr), \
	X(sys_fork), \
	X(sys_fremovexattr), \
	X(sys_fstat64), \
	X(sys_ftruncate64), \
	X(sys_futimesat), \
	X(sys_getcwd), \
	X(sys_getpeername), \
	X(sys_getsockname), \
	X(sys_getsockopt), \
	X(sys_getxattr), \
	X(sys_inotify_add_watch), \
	X(sys_inotify_init1), \
	X(sys_inotify_init), \
	X(sys_inotify_rm_watch), \
	X(sys_ipc), \
	X(sys_kill), \
	X(sys_linkat), \
	X(sys_link), \
	X(sys_listen), \
	X(sys_listxattr), \
	X(sys_lstat64), \
	X(sys_lstat), \
	X(sys_mkdirat), \
	X(sys_mkdir), \
	X(sys_mknodat), \
	X(sys_mknod), \
	X(sys_mmap_pgoff), \
	X(sys_mount), \
	X(sys_msgctl), \
	X(sys_msgget), \
	X(sys_msgrcv), \
	X(sys_msgsnd), \
	X(sys_name_to_handle_at), \
	X(sys_newfstatat), \
	X(sys_old_mmap), \
	X(sys_openat), \
	X(sys_open_by_handle_at), \
	X(sys_open), \
	X(sys_pause), \
	X(sys_pipe2), \
	X(sys_ppoll), \
	X(sys_pread64), \
	X(sys_preadv), \
	X(sys_pselect6), \
	X(sys_pwrite64), \
	X(sys_pwritev), \
	X(sys_readlinkat), \
	X(sys_readlink), \
	X(sys_recvfrom), \
	X(sys_recvmmsg), \
	X(sys_recvmsg), \
	X(sys_recv), \
	X(sys_removexattr), \
	X(sys_renameat), \
	X(sys_rename), \
	X(sys_rmdir), \
	X(sys_rt_sigaction), \
	X(sys_rt_sigprocmask), \
	X(sys_rt_sigsuspend), \
	X(sys_rt_sigtimedwait), \
	X(sys_rt_tgsigqueueinfo), \
	X(sys_semctl), \
	X(sys_semget), \
	X(sys_semop), \
	X(sys_semtimedop), \
	X(sys_sendfile64), \
	X(sys_sendfile), \
	X(sys_sendmmsg), \
	X(sys_sendmsg), \
	X(sys_send), \
	X(sys_sendto), \
	X(sys_setns), \
	X(sys_setsockopt), \
	X(sys_setxattr), \
	X(sys_shmat), \
	X(sys_shmctl), \
	X(sys_shmdt), \
	X(sys_shmget), \
	X(sys_shutdown), \
	X(sys_sigaction), \
	X(sys_sigaltstack), \
	X(sys_signalfd4), \
	X(sys_signalfd), \
	X(sys_signal), \
	X(sys_sigpending), \
	X(sys_sigprocmask), \
	X(sys_sigsuspend), \
	X(sys_socketcall), \
	X(sys_socketpair), \
	X(sys_socket), \
	X(sys_splice), \
	X(sys_stat64), \
	X(sys_statfs64), \
	X(sys_statfs), \
	X(sys_stat), \
	X(sys_swapoff), \
	X(sys_swapon), \
	X(sys_symlinkat), \
	X(sys_symlink), \
	X(sys_syncfs), \
	X(sys_tee), \
	X(sys_tgkill), \
	X(sys_timerfd_create), \
	X(sys_timerfd_gettime), \
	X(sys_timerfd_settime), \
	X(sys_truncate64), \
	X(sys_truncate), \
	X(sys_umount), \
	X(sys_unlinkat), \
	X(sys_unlink), \
	X(sys_unshare), \
	X(sys_uselib), \
	X(sys_utimensat), \
	X(sys_utimes), \
	X(sys_utime), \
	X(sys_vfork), \
	X(sys_vmsplice), \
	X(sys_wait4), \
	X(sys_waitid), \
	X(sys_waitpid)

#define X(x) #x
static const char *const syscall_name[] = {
	SYSCALL_LIST
};
#undef X

enum {
	syscall_name_cnt = sizeof(syscall_name) / sizeof(char *)
};

#define X(x) id_##x
enum syscall_id {
	SYSCALL_LIST
};
#undef X

#undef SYSCALL_LIST

static char sys_counter[syscall_name_cnt] = { 0 };

static enum syscall_id id_file[] = {
	id_sys_acct,
	id_sys_mount,
	id_sys_umount,
	id_sys_truncate,
	id_sys_stat,
	id_sys_statfs,
	id_sys_statfs64,
	id_sys_lstat,
	id_sys_stat64,
	id_sys_fstat64,
	id_sys_lstat64,
	id_sys_truncate64,
	id_sys_ftruncate64,
	id_sys_setxattr,
	id_sys_getxattr,
	id_sys_listxattr,
	id_sys_removexattr,
	id_sys_chroot,
	id_sys_mknod,
	id_sys_link,
	id_sys_symlink,
	id_sys_unlink,
	id_sys_rename,
	id_sys_chmod,
	id_sys_readlink,
	id_sys_creat,
	id_sys_open,
	id_sys_access,
	id_sys_chown,
	id_sys_chown16,
	id_sys_utime,
	id_sys_utimes,
	id_sys_pread64,
	id_sys_pwrite64,
	id_sys_preadv,
	id_sys_pwritev,
	id_sys_getcwd,
	id_sys_mkdir,
	id_sys_chdir,
	id_sys_rmdir,
	id_sys_swapon,
	id_sys_swapoff,
	id_sys_uselib,
	id_sys_mknodat,
	id_sys_mkdirat,
	id_sys_unlinkat,
	id_sys_symlinkat,
	id_sys_linkat,
	id_sys_renameat,
	id_sys_futimesat,
	id_sys_faccessat,
	id_sys_fchmodat,
	id_sys_fchownat,
	id_sys_openat,
	id_sys_newfstatat,
	id_sys_readlinkat,
	id_sys_utimensat,
	id_sys_fanotify_mark,
	id_sys_execve,
	id_sys_name_to_handle_at,
	id_sys_open_by_handle_at
};

static enum syscall_id id_irq[] = {
	id_sys_msgget,
	id_sys_msgsnd,
	id_sys_msgrcv,
	id_sys_msgctl,
	id_sys_semget,
	id_sys_semop,
	id_sys_semctl,
	id_sys_semtimedop,
	id_sys_shmat,
	id_sys_shmget,
	id_sys_shmdt,
	id_sys_shmctl,
	id_sys_ipc
};

static enum syscall_id id_net[] = {
	id_sys_shutdown,
	id_sys_sendfile,
	id_sys_sendfile64,
	id_sys_setsockopt,
	id_sys_getsockopt,
	id_sys_bind,
	id_sys_connect,
	id_sys_accept,
	id_sys_accept4,
	id_sys_getsockname,
	id_sys_getpeername,
	id_sys_send,
	id_sys_sendto,
	id_sys_sendmsg,
	id_sys_sendmmsg,
	id_sys_recv,
	id_sys_recvfrom,
	id_sys_recvmsg,
	id_sys_recvmmsg,
	id_sys_socket,
	id_sys_socketpair,
	id_sys_socketcall,
	id_sys_listen
};

static enum syscall_id id_process[] = {
	id_sys_exit,
	id_sys_exit_group,
	id_sys_wait4,
	id_sys_waitid,
	id_sys_waitpid,
	id_sys_rt_tgsigqueueinfo,
	id_sys_unshare,
	id_sys_fork,
	id_sys_vfork,
/* TODO: add support CONFIG_CLONE_BACKWARDS
 *	id_sys_clone,
 *	id_sys_clone,
 */
    id_sys_execve
};

static enum syscall_id id_signal[] = {
	id_sys_sigpending,
	id_sys_sigprocmask,
	id_sys_sigaltstack,
/* TODO: add support CONFIG_OLD_SIGSUSPEND and CONFIG_OLD_SIGSUSPEND3
 *	id_sys_sigsuspend,
 *	id_sys_sigsuspend,
 */
	id_sys_rt_sigsuspend,
	id_sys_sigaction,
	id_sys_rt_sigaction,
	id_sys_rt_sigprocmask,
	id_sys_rt_sigtimedwait,
	id_sys_rt_tgsigqueueinfo,
	id_sys_kill,
	id_sys_tgkill,
	id_sys_signal,
	id_sys_pause,
	id_sys_signalfd,
	id_sys_signalfd4
};

static enum syscall_id id_desc[] = {
	id_sys_fgetxattr,
	id_sys_flistxattr,
	id_sys_fremovexattr,
	id_sys_fadvise64_64,
	id_sys_pipe2,
	id_sys_dup3,
	id_sys_sendfile,
	id_sys_sendfile64,
	id_sys_preadv,
	id_sys_pwritev,
	id_sys_epoll_create1,
	id_sys_epoll_ctl,
	id_sys_epoll_wait,
	id_sys_epoll_pwait,
	id_sys_inotify_init,
	id_sys_inotify_init1,
	id_sys_inotify_add_watch,
	id_sys_inotify_rm_watch,
	id_sys_mknodat,
	id_sys_mkdirat,
	id_sys_unlinkat,
	id_sys_symlinkat,
	id_sys_linkat,
	id_sys_renameat,
	id_sys_futimesat,
	id_sys_faccessat,
	id_sys_fchmodat,
	id_sys_fchownat,
	id_sys_openat,
	id_sys_newfstatat,
	id_sys_readlinkat,
	id_sys_utimensat,
	id_sys_splice,
	id_sys_vmsplice,
	id_sys_tee,
	id_sys_signalfd,
	id_sys_signalfd4,
	id_sys_timerfd_create,
	id_sys_timerfd_settime,
	id_sys_timerfd_gettime,
	id_sys_eventfd,
	id_sys_eventfd2,
	id_sys_fallocate,
	id_sys_pselect6,
	id_sys_ppoll,
	id_sys_fanotify_init,
	id_sys_fanotify_mark,
	id_sys_syncfs,
	id_sys_mmap_pgoff,
	id_sys_old_mmap,
	id_sys_name_to_handle_at,
	id_sys_setns
};

struct feature {
	size_t cnt;
	enum syscall_id *feature_list;
};

#define CREATE_FEATURE(x) 				\
{ 							\
	.cnt = sizeof(x) / sizeof(enum syscall_id),	\
	.feature_list = x				\
}

static struct feature features[] = {
	CREATE_FEATURE(id_file),
	CREATE_FEATURE(id_irq),
	CREATE_FEATURE(id_net),
	CREATE_FEATURE(id_process),
	CREATE_FEATURE(id_signal),
	CREATE_FEATURE(id_desc)
};

#undef CREATE_FEATURE

enum {
	feature_cnt = sizeof(features) / sizeof(struct feature)
};

#endif /* _FEATURES_DATA_H */
