import idc
import idaapi
import struct

ROM_SIGNATURE_OFFSET 	= 0
ROM_SIGNATURE 		= "NES\x1A"
ROM_FORMAT_NAME        	= "Nintendo NES ROM"
ROM_SIGNATURE_LENGTH 	= 4
HEADER_SIZE		= 16
PRG_PAGE_SIZE		= 0x4000
CHR_PAGE_SIZE		= 0x2000
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

MAPPER_NONE		= 0
MAPPER_MMC1		= 1
MAPPER_UxROM		= 2
MAPPER_CNROM		= 3
MAPPER_MMC3		= 4
MAPPER_MMC5		= 5
MAPPER_AxROM		= 7
MAPPER_MMC2		= 9
MAPPER_MMC4		= 10
MAPPER_COLOR_DREAMS	= 11
MAPPER_CPROM		= 13
MAPPER_BxROM		= 34
MAPPER_GNROM		= 66
MAPPER_CAMERICA		= 71
MAPPER_TLSROM		= 118
MAPPER_TQROM		= 119


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
	CartTypeLSB = struct.unpack("<B", li.read(1))[0]
	# SRAM
	if (((CartTypeLSB & 0x2) >> 1) == 1):
		idc.AddSeg(SRAM_START, SRAM_START + SRAM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
		idc.RenameSeg(SRAM_START, "SRAM")

	# EXPROM
	idc.AddSeg(EXPROM_START, EXPROM_START + EXPROM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(EXPROM_START, "EXPROM")

	# TRAINER
	if (((CartTypeLSB & 0x4) >> 2) == 1):
		idc.AddSeg(TRAINER_START, TRAINER_START + TRAINER_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
		idc.RenameSeg(TRAINER_START, "TRAINER")

	# ROM
	idc.AddSeg(ROM_START, ROM_START + ROM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM_START, "ROM")	
	idc.SetSegmentType(ROM_START, idc.SEG_CODE)

	CartTypeMSB = struct.unpack("<B", li.read(1))[0]
	mapper_version = (((CartTypeLSB & 0xF0) >> 4) | (CartTypeMSB & 0xF0))
	if (mapper_version == MAPPER_NONE or
		mapper_version == MAPPER_MMC1 or
		mapper_version == MAPPER_UxROM or
		mapper_version == MAPPER_CNROM or
		mapper_version == MAPPER_MMC3 or
		mapper_version == MAPPER_MMC5 or
		mapper_version == MAPPER_CAMERIC or
		mapper_version == MAPPER_GNROM):
		li.seek(0x4)
		prg_rom_size = struct.unpack("<B", li.read(1))[0]
		if (prg_rom_size != 0):
			offset = HEADER_SIZE
			if (((CartTypeLSB & 0x4) >> 2) == 1):
				offset += TRAINER_SIZE
			li.seek(offset)
			li.file2base(0, ROM_START, ROM_START + PRG_PAGE_SIZE, 0)
			offset = HEADER_SIZE + (prg_rom_size - 1) * PRG_PAGE_SIZE
			if (((CartTypeLSB & 0x4) >> 2) == 1):
				offset += TRAINER_SIZE
			li.seek(offset)
			li.file2base(0, ROM_START + PRG_PAGE_SIZE, ROM_START + PRG_PAGE_SIZE + PRG_PAGE_SIZE, 0)

	elif (mapper_version == MAPPER_MMC2):
		print("Second case mapper")
	elif (mapper_version == MAPPER_AxROM or
		mapper_version == MAPPER_COLOR_DREAMS or
		mapper_version == MAPPER_BxROM):
		print("Third case mapper")
	else:
		print("Mapper %d is not supported" % mapper_version)

	naming()
	idaapi.add_entry(Word(0xFFFC), Word(0xFFFC), "start", 1)
	idaapi.cvar.inf.startIP = Word(0xFFFC)
	idaapi.cvar.inf.beginEA = Word(0xFFFC)	


	print("[+] Load OK")
	return 1

def naming():
	MakeNameEx(0xFFFA, "NMI_vector", SN_NOCHECK | SN_NOWARN)
	MakeWord(0xFFFA)
	MakeNameEx(0xFFFC, "RESET_vector", SN_NOCHECK | SN_NOWARN)
	MakeWord(0xFFFC)
	MakeNameEx(0xFFFE, "IRQ_vector", SN_NOCHECK | SN_NOWARN)
	MakeWord(0xFFFE)

