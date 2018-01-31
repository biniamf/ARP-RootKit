#ifndef HOOKING_H

extern int my_sock_recvmsg(struct socket *sock, struct msghdr *msg, int flags);

#define HOOKING_H
#endif
