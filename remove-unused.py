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
# This removes unused ASM code from the sources, to make it more generic.
#

import sys
import re

def remove_func(symbol, data):
	#pattern = "(\t\.type[\s]+" + symbol + ",[\s\S]*?\.\-" + symbol + "\n)"
	pattern = "([\s]*?\.type[\s]+" + symbol + ",[\s\S]*?\.\-" + symbol + ")"
	regex = re.compile(pattern)
	for match in regex.findall(data):
		data = data.replace(match, '')
	return data

if len(sys.argv) < 2:
	print "use: " + sys.argv[0] + " <file>"
	sys.exit(-1)

f = open(sys.argv[1], "r")
data = f.read()
f.close()

# remove problematic and unused funcs
data = remove_func("__phys_addr_nodebug", data)
data = remove_func("pmd_to_page", data)
data = remove_func("mem_cgroup_nodeinfo", data)
data = remove_func("__check_printsym_format", data)

print data
