import subprocess
import sys
import os
import re
import struct
from capstone_python import *
from capstone_python.x86 import *

def find_sct(vmlinux, secdata):
	cmd = "objcopy --dump-section .rodata=" + secdata + " " + vmlinux
	if os.system(cmd):
		os.remove(secdata)
		return -1
	out = subprocess.check_output(["readelf", "-t", "--wide", vmlinux])
	#.text
    #   PROGBITS        ffffffff81000000 200000 c031d1 
	pattern = "\.text\n\s*?PROGBITS\s*?([a-z0-9]{16}) \d+ ([a-z0-9]{0,16}?) "
	regex = re.compile(pattern)
	out = out.decode('utf-8')
	match = regex.findall(out)
	code_start = int(match[0][0], 16)
	code_end = code_start + int(match[0][1], 16)
	f = open(secdata, 'rb')
	c = 0
	while True:
		data = f.read(8)
		if data == '' or len(data) < 8:
			break
		data = struct.unpack("=Q", data)
		data = data[0] 
		if data >= code_start and data <= code_end:
			c += 1
			#if (c >= 500):
			#	print("%d found sct!" % c)
		else:
			if c > 500 and c < 600:
				print("Found sct! %d syscalls" % c)
			c = 0
	f.close()
	os.remove(secdata)
	return 0

vmlinuz = sys.argv[1]
vmlinux = "vmlinux"
cmd = "./extract-vmlinux " + vmlinuz + " > " + vmlinux + " 2>/dev/null"
if os.system(cmd):
	sys.exit(-1)
secdata = vmlinux + ".data"
find_sct(vmlinux, secdata)
sys.exit(0)
code = vmlinux + ".code"
cmd = "objcopy --dump-section .text=" + code + " " + vmlinux
if os.system(cmd):
	os.remove(vmlinux)
	sys.exit(-1)

f = open(code, "rb")
CODE = f.read()
f.close()

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0):
	print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

os.remove(vmlinux)
