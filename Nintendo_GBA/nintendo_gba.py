import idc 
import idaapi
import struct

ROM_SIGNATURE_OFFSET 	= 4
ROM_SIGNATURE        	= "\x24\xFF\xAE\x51" # TO FIX more than 4 bytes
ROM_FORMAT_NAME        	= "Nintendo GBA ROM"
SIZE_HEADER		= 0xC0
ROM_START		= 0x08000000
ROM_SIZE		= 0x01000000

def dwordAt(li, off):
	li.seek(off)
	s = li.read(4)
	if len(s) < 4: 
		return 0
	return struct.unpack('<I', s)[0]


def accept_file(li, n):
	# we support only one format per file
    	if n > 0:
        	return 0

	# check the Nintendo Logo
	li.seek(ROM_SIGNATURE_OFFSET)
	if li.read(4) == ROM_SIGNATURE:
		# accept the file
		return ROM_FORMAT_NAME

	# unrecognized format
	return 0

def load_file(li, neflags, format):
	if format == ROM_FORMAT_NAME:
        	jump = dwordAt(li, 0)
		# Test ARM branch
        	if jump & 0xFF000000 == 0xEA000000:
            		idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
        		li.seek(0, idaapi.SEEK_END)
        		size = li.tell()

			# Adding Header Section
			idc.AddSeg(ROM_START, ROM_START + SIZE_HEADER, 0, 1, idaapi.saRelPara, idaapi.scPub)
			idc.RenameSeg(ROM_START, "HEADER")
			li.seek(0)
        		li.file2base(0, ROM_START, ROM_START + SIZE_HEADER, 0)

			# Adding ROM Section
			idc.AddSeg(ROM_START + SIZE_HEADER, ROM_START + (ROM_SIZE - SIZE_HEADER), 0, 1, idaapi.saRelPara, idaapi.scPub)
			idc.RenameSeg(ROM_START + SIZE_HEADER, "ROM")
			print("READING %X" % (size - SIZE_HEADER))
			li.seek(SIZE_HEADER)
        		li.file2base(0, ROM_START + SIZE_HEADER, ROM_START + size, 0)

			# Adding OEP
			idaapi.add_entry(ROM_START, ROM_START, "start", 1)

			# Adding EWRAM
			idc.AddSeg(0x02000000, 0x02040000, 0, 1, idaapi.saRelPara, idaapi.scPub)
			idc.RenameSeg(0x02000000, "EWRAM")

			# Adding IWRAM
			idc.AddSeg(0x03000000, 0x03008000, 0, 1, idaapi.saRelPara, idaapi.scPub)
			idc.RenameSeg(0x02000000, "IWRAM")

			print("[+] Load OK")
			return 1
	Warning("Unknown format name: '%s'" % format)
    	return 0


def main():
	return 0
