import idc
import idaapi
import struct

ROM_SIGNATURE_OFFSET 	= 0
ROM_SIGNATURE 		= "NES\x1A"
ROM_SIGNATURE_LENGTH 	= 4
RAM_START 		= 0x0
RAM_SIZE		= 0x2000
SRAM_START		= 0x6000
SRAM_SIZE		= 0x2000
TRAINER_START		= 0x7000
TRAINER_SIZE		= 0x0200
ROM_START		= 0x8000
ROM_SIZE		= 0x8000
EXPROM_START		= 0x4020
EXPROM_SIZE		= 0x1FE0

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
	idaapi.set_processor_type("M6502", SETPROC_ALL | SETPROC_FATAL)
	li.seek(0, idaapi.SEEK_END)
	size = li.tell()

	# RAM
	idc.AddSeg(RAM_START, RAM_START + RAM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(RAM_START, "RAM")

	li.seek(0x6)
	CartType = struct.unpack("<B", li.read(1))[0]
	# SRAM
	if (((CartType & 0x2) >> 1) == 1):
		idc.AddSeg(SRAM_START, SRAM_START + SRAM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
		idc.RenameSeg(SRAM_START, "SRAM")

	# EXPROM
	idc.AddSeg(EXPROM_START, EXPROM_START + EXPROM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(EXPROM_START, "EXPROM")

	# TRAINER
	if (((CartType & 0x4) >> 2) == 1):
		idc.AddSeg(TRAINER_START, TRAINER_START + TRAINER_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
		idc.RenameSeg(TRAINER_START, "TRAINER")

	# ROM
	idc.AddSeg(ROM_START, ROM_START + ROM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM_START, "ROM")	
