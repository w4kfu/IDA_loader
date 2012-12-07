import idc 
import idaapi
import struct

ROM_SIGNATURE_OFFSET 	= 0x104
ROM_SIGNATURE        	= "\xCE\xED\x66\x66\xCC\x0D\x00\x0B\x03\x73\x00\x83\x00\x0C\x00\x0D"
ROM_SIGNATURE		+= "\x00\x08\x11\x1F\x88\x89\x00\x0E\xDC\xCC\x6E\xE6\xDD\xDD\xD9\x99"
ROM_SIGNATURE		+= "\xBB\xBB\x67\x63\x6E\x0E\xEC\xCC\xDD\xDC\x99\x9F\xBB\xB9\x33\x3E"
ROM_SIGNATURE_LENGTH	= 0x30
ROM_FORMAT_NAME        	= "Nintendo GB ROM"
SIZE_HEADER		= 0x150
ROM0_START		= 0
ROM0_SIZE		= 0x4000
ROM1_START		= 0x4000
ROM1_SIZE		= 0x4000
VRAM_START		= 0x8000
VRAM_SIZE		= 0x2000
RAM1_START		= 0xA000
RAM1_SIZE		= 0x2000
RAM0_START		= 0xC000
RAM0_SIZE		= 0x2000
ECHO_START		= 0xE000
ECHO_SIZE		= 0x1E00
OAM_START		= 0xFE00
OAM_SIZE		= 0xA0
IO_START		= 0xFEA0
IO_SIZE			= 0xE0
HRAM_START		= 0xFF80
HRAM_SIZE		= 0x80

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
	if li.read(ROM_SIGNATURE_LENGTH) == ROM_SIGNATURE:
		# accept the file
		return ROM_FORMAT_NAME

	# unrecognized format
	return 0

def load_file(li, neflags, format):
	if format != ROM_FORMAT_NAME:
		Warning("Unknown format name: '%s'" % format)
    		return 0
	jump = dwordAt(li, 0)
	idaapi.set_processor_type("gb", SETPROC_ALL|SETPROC_FATAL)
	li.seek(0, idaapi.SEEK_END)
	size = li.tell()

	# ROM0
	idc.AddSeg(ROM0_START, ROM0_START + ROM0_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM0_START, "ROM0")
	idc.SetSegmentType(ROM0_START, idc.SEG_CODE)
	li.seek(0)
	li.file2base(0, ROM0_START, ROM0_START + ROM0_SIZE, 0)

	# ROM1
	idc.AddSeg(ROM1_START, ROM1_START + ROM1_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM1_START, "ROM1")
	idc.SetSegmentType(ROM1_START, idc.SEG_CODE)

	# VRAM
	idc.AddSeg(VRAM_START, VRAM_START + VRAM_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(VRAM_START, "VRAM")

	# RAM1
	idc.AddSeg(RAM1_START, RAM1_START + RAM1_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(RAM1_START, "RAM1")

	# RAM0
	idc.AddSeg(RAM0_START, RAM0_START + RAM0_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(RAM0_START, "RAM0")

	# ECHO
	idc.AddSeg(ECHO_START, ECHO_START + ECHO_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ECHO_START, "ECHO")

	# OAM
	idc.AddSeg(OAM_START, OAM_START + OAM_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(OAM_START, "OAM")

	# IO
	idc.AddSeg(IO_START, IO_START + IO_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(IO_START, "IO")

	# HRAM
	idc.AddSeg(HRAM_START, HRAM_START + HRAM_SIZE, 0, 1, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(HRAM_START, "HRAM")

	print("[+] Load OK")
	return 1

def main():
	return 0
