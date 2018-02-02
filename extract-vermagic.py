#!/usr/bin/python
#
## License:
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
## Description:
#
# Searches the VERSION_MAGIC macro value defined in Linux Kernel headers,
# for the current kernel.
# It searches in /proc/kcore, vmlinuz images, and Linux Kernel Modules.
#
## Dependencies:
#
# 1) readelf
# 2) objcopy
# 3) extract-vmlinux deps
#

import sys
import platform
import re
import os
import subprocess

# max memory range size
kcore_max_size = 0x03000000
kcore_min_size = 0x01000000

def search_in_data (data, ref):
    # search vermagic
    pattern = "(" + re.escape(ref) + " " + ".*?\x00)"
    #print "Reference is release: " + ref
    #print "Searching by regex hex pattern: " + pattern
    regex = re.compile(pattern)
    matches = []
    for match in regex.findall(data):
        length = len(match)
        remaining = (8 - (length % 8))
        pattern = "(" + re.escape(match) + "\x00" * remaining + "(?:(?:\x00{0})|(?:\x00{8})|(?:\x00{16})|(?:\x00{24})))(?!\x00)"
        #print "\"" + match + "\""
        #print length
        #print remaining
        #print pattern
        #print pattern.encode('hex')
        regex = re.compile(pattern)
        for match in regex.findall(data):
            #print "Match!"
            #print match_obj.encode('hex')
            #print len(match_obj)
            #print "Found vermagic: \"" + match + "\""
            matches.append(match)
    return matches

def search_in_vmlinuz(vmlinuz, ref):
	vmlinux = "uncompressed.vmlinux"

	# decompress vmlinuz image
	cmd = "./extract-vmlinux " + vmlinuz + " > " + vmlinux + " 2>/dev/null"
	#print cmd
	os.system(cmd)
	#sys.exit(0)
	# load vmlinux binary
	f = open(vmlinux, 'rb')
	data = f.read()
	f.close()

	# remove vmlinux binary
	#os.remove(vmlinux)

	matches = search_in_data(data, ref)
	return matches

def search_in_kcore(ref):
	if not os.path.exists("/proc/kcore") or not os.path.isfile("/proc/kcore"):
		return ""

	matches = []
	# read kernel binary from /proc/kcore (with readelf -e -g -t /proc/kcore)
	out = subprocess.check_output(['readelf', '-e', '-g', '-t', '/proc/kcore'])
	pattern = ' (0x\S*?) 0x\S*? .*?\n.*? (0x\S*?) '
	regex = re.compile(pattern, re.MULTILINE)
	ranges = regex.findall(out)
	for _range in ranges:
		off = int(_range[0], 16)
		size = int(_range[1], 16)
		if size > kcore_max_size or size < kcore_min_size:
			continue
		f = open("/proc/kcore", 'rb')
		f.seek(off, os.SEEK_SET)
		data = f.read(size)
		f.close()
		for match in search_in_data(data, ref):
			#print match
			matches.append(match)
	return matches

def search_in_module(lkm, ref):
	sectfile = "module.modinfo"

	# dump .modinfo of LKM
	os.system("objcopy --dump-section .modinfo=" + sectfile + " " + lkm)

	# load dumped section file
	f = open(sectfile, 'rb')
	data = f.read()
	f.close()

	# remove sectfile
	os.remove(sectfile)

	# replace vermagic
	pattern = "vermagic=(" + ref + " .*?)\x00"
	regex = re.compile(pattern)
	matches = regex.findall(data)
	return matches

def search_in_modules(ref):
	matches = []
	for root, subdirs, files in os.walk("/lib/modules"):
		for _file in files:
			if _file.endswith(".ko"):
				path = root + "/" + _file
				for match in search_in_module(path, ref):
					matches.append(match)
	return matches

def search_in_images(ref):
	matches = []
	for root, subdirs, files in os.walk("/boot"):
		for _file in files:
			path = root + "/" + _file
			for match in search_in_vmlinuz(path, ref):
				matches.append(match)
	return matches

ref = platform.release()
matches = []

# search vermagic in all .ko files inside /lib/modules, filtering by ref
matches = list(set(search_in_modules(ref)))
for match in matches:
	print "Found in modules: " + match

# search vermagic in all compressend Linux Kernel images in /boot, filtering by ref
matches = list(set(search_in_images(ref)))
for match in matches:
	print "Found in images: " + match

# search vermagic in the memory areas with size in [kcore_min_size, kcore_max_size], filtering by ref
matches = list(set(search_in_kcore(ref)))
for match in matches:
	print "Found in /proc/kcore: " + match
