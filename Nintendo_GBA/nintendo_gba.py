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

def memset_seg(ea, size):
	for i in xrange(0, size):
		idc.PatchByte(ea + i, 0)

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
	if format != ROM_FORMAT_NAME:
		Warning("Unknown format name: '%s'" % format)
    		return 0
	jump = dwordAt(li, 0)
	# Test ARM branch
	if jump & 0xFF000000 != 0xEA000000:
		Warning("Unknown format name: '%s'" % format)
    		return 0
	idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
	li.seek(0, idaapi.SEEK_END)
	size = li.tell()

	# Adding Header Section
	idc.AddSeg(ROM_START, ROM_START + SIZE_HEADER, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM_START, "HEADER")
	idc.SetSegmentType(ROM_START, idc.SEG_CODE)
	li.seek(0)
	li.file2base(0, ROM_START, ROM_START + SIZE_HEADER, 0)

	# Adding OEP
	idaapi.add_entry(ROM_START, ROM_START, "start", 1)
	idaapi.cvar.inf.startIP = ROM_START
	idaapi.cvar.inf.beginEA = ROM_START

	# Adding ROM Section
	idc.AddSeg(ROM_START + SIZE_HEADER, ROM_START + (ROM_SIZE - SIZE_HEADER), 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM_START + SIZE_HEADER, "ROM")
	idc.SetSegmentType(ROM_START + SIZE_HEADER, idc.SEG_CODE)
	li.seek(SIZE_HEADER)
	li.file2base(0, ROM_START + SIZE_HEADER, ROM_START + size, 0)

	# Adding EWRAM
	idc.AddSeg(0x02000000, 0x02040000, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(0x02000000, "EWRAM")
	memset_seg(0x02000000, 0x40000)

	# Adding IWRAM
	idc.AddSeg(0x03000000, 0x03008000, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(0x03000000, "IWRAM")
	memset_seg(0x03000000, 0x8000)

	# Adding IO / Registers
	idc.AddSeg(0x04000000, 0x04000400, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(0x04000000, "IOregisters")
	memset_seg(0x04000000, 0x400)

	# Adding BIOS System ROM
	idc.AddSeg(0x00000000, 0x00004000, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(0x00000000, "BIOS")
	memset_seg(0x00000000, 0x4000)
	idc.SetSegmentType(0x0000000, idc.SEG_CODE)

	idaapi.add_long_cmt(ROM_START, True, "ROM HEADER")
	li.seek(0xA0)
	idc.ExtLinA(ROM_START, 1,  "; Game Title : %s" % li.read(12))
	idc.ExtLinA(ROM_START, 2,  "; Game Code : %s" % li.read(4))
	idc.ExtLinA(ROM_START, 3,  "; Marker Code : %s" % li.read(2))
	idc.ExtLinA(ROM_START, 4,  "; Fixed value : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(ROM_START, 5,  "; Main unit code : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(ROM_START, 6,  "; Device type : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(ROM_START, 7,  "; Reserved Area db(7h)")
	li.read(7)
	idc.ExtLinA(ROM_START, 8,  "; Software version %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(ROM_START, 9,  "; Complement Check %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(ROM_START, 10,  "; Reserved Area db(2h)")

	print("[+] Load OK")
	return 1


def main():
	return 0
