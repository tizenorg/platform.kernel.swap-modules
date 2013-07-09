#include "syscall_list.h"

struct feature {
	size_t cnt;
	enum syscall_id *feature_list;
};

#define X(name, args) id_##name
enum syscall_id {
	SYSCALL_LIST
};
#undef X

static enum syscall_id id_file[] = {
	id_sys_acct,
	id_sys_mount,
	id_sys_umount,
	id_sys_truncate,
/* TODO:
 *	id_sys_stat,
 */
	id_sys_statfs,
	id_sys_statfs64,
/* TODO:
 *	id_sys_lstat,
 */
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
/* TODO:
 *	id_sys_newfstatat,
 */
	id_sys_readlinkat,
	id_sys_utimensat,
	id_sys_fanotify_mark,
	id_sys_execve,
	id_sys_name_to_handle_at,
	id_sys_open_by_handle_at
};

static enum syscall_id id_ipc[] = {
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
/* TODO:
 *	id_sys_waitpid,
 */
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
/* TODO:
 *	id_sys_sigaltstack,
 */
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
/* TODO:
 *	id_sys_signal,
 */
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
/* TODO:
 *	id_sys_newfstatat,
 */
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

#define CREATE_FEATURE(x)	 				\
{ 								\
	.cnt = sizeof(x) / sizeof(enum syscall_id),		\
	.feature_list = x					\
}

static struct feature features[] = {
	CREATE_FEATURE(id_file),
	CREATE_FEATURE(id_ipc),
	CREATE_FEATURE(id_net),
	CREATE_FEATURE(id_process),
	CREATE_FEATURE(id_signal),
	CREATE_FEATURE(id_desc)
};

enum {
	feature_cnt = sizeof(features) / sizeof(struct feature)
};
