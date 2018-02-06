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
