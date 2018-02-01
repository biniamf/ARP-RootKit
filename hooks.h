#ifndef HOOKS_H

/*
 * (Un)Hooking macros.
 */
#define HOOK64(nr, handler) my_sct[nr] = handler
#define HOOK32(nr, handler) my_ia32sct[nr] = handler
#define UNHOOK64(nr) my_sct[nr] = sys_call_table[nr]
#define UNHOOK32(nr) my_ia32sct[nr] = ia32_sys_call_table[nr]

/*
 * Hook handlers.
 */
extern int my_recvfrom64(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern int my_recvfrom32(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern int my_read64(int fd, void __user *buf, size_t len);
extern int my_read32(int fd, void __user *buf, size_t len);

#define HOOKS_H
#endif
