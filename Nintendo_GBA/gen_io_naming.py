import re

INPUT_FILE = "io_registers.txt"

f = open(INPUT_FILE, 'r')
for line in f.readlines():
	value = re.sub("\s+" , " ", line).split(' ')
	if (value[1] == '?'):
		continue
	index = 4
	if (value[1] == '-'):
		index = 3
	print("MakeNameEx(0x%08X, \"%s\", SN_NOCHECK | SN_NOWARN)" % (int(value[0].replace("h", ""), 16), ''.join(value[index:])))
	if (value[1] == '1'):
		print("MakeByte(0x%08X)" % (int(value[0].replace("h", ""), 16)))
	elif (value[1] == '2'):
		print("MakeWord(0x%08X)" % (int(value[0].replace("h", ""), 16)))
	elif (value[1] == '4'):
		print("MakeDword(0x%08X)" % (int(value[0].replace("h", ""), 16)))		
