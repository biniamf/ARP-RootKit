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
 * This defines the struct module this_module as a 1000bytes sized area.
 * Because we don't know which size has on the kernel where it's going to run.
 * And after resizing with objcopy, the .rela.gnu.linkonce.this_module
 * becomes 0 sized. So, we define the size here and patch later.
 */

#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct mymod {
	char zero1[24];
	char name[MODULE_NAME_LEN]; // 24:  56
	void *init, *exit;			// 80:   8
	char zero2[912];            // 88:  912
	// 1000: 
} mymod
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
	.exit = cleanup_module
};

extern struct module __this_module __attribute__ ((section(".gnu.linkonce.this_module"), alias ("mymod")));

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

