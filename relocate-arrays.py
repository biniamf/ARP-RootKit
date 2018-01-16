#!/usr/bin/env python
import re
import sys 

with open('kernel-asm.s', 'r') as myfile:
    data = myfile.read()

#m = re.findall('(\.LC[0-9]+\:\n\t\.string\t\"[\s\S]{0,}?\"\n(?:\t\.align [0-9]{0,}\n){0,1})', re.search('code_start:([\S\s]{0,})?code_end:', data, re.MULTILINE).group(0), re.MULTILINE);
m = re.findall('(\S+)\:\n\t\.string\t\"[\s\S]{0,}?\"\n', data, re.MULTILINE);

for s in m:
#	print("Relocating array " + s)
	data = data.replace("$" + s, s + "(%rip)")

sys.stdout.write(data)
