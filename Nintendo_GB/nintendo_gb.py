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
	idc.AddSeg(ROM0_START, ROM0_START + ROM0_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM0_START, "ROM0")
	idc.SetSegmentType(ROM0_START, idc.SEG_CODE)
	li.seek(0)
	li.file2base(0, ROM0_START, ROM0_START + ROM0_SIZE, 0)

	# ROM1
	idc.AddSeg(ROM1_START, ROM1_START + ROM1_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ROM1_START, "ROM1")
	idc.SetSegmentType(ROM1_START, idc.SEG_CODE)

	# VRAM
	idc.AddSeg(VRAM_START, VRAM_START + VRAM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(VRAM_START, "VRAM")

	# RAM1
	idc.AddSeg(RAM1_START, RAM1_START + RAM1_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(RAM1_START, "RAM1")

	# RAM0
	idc.AddSeg(RAM0_START, RAM0_START + RAM0_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(RAM0_START, "RAM0")

	# ECHO
	idc.AddSeg(ECHO_START, ECHO_START + ECHO_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(ECHO_START, "ECHO")

	# OAM
	idc.AddSeg(OAM_START, OAM_START + OAM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(OAM_START, "OAM")

	# IO
	idc.AddSeg(IO_START, IO_START + IO_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(IO_START, "IO")

	# HRAM
	idc.AddSeg(HRAM_START, HRAM_START + HRAM_SIZE, 0, 0, idaapi.saRelPara, idaapi.scPub)
	idc.RenameSeg(HRAM_START, "HRAM")

	header_info(li)
	naming()
	print("[+] Load OK")
	return 1

def header_info(li):
	idaapi.add_long_cmt(0, True, "-------------------------------")
	li.seek(0x100)
	idc.ExtLinA(0, 1,  "; ROM HEADER")
	idc.ExtLinA(0, 2,  "; Entry Point : %04X" % (struct.unpack("<I", li.read(4))[0] >> 0x10))
	li.read(0x30)
	idc.ExtLinA(0, 3,  "; TITLE : %s" % li.read(0xF))
	idc.ExtLinA(0, 4,  "; Manufacturer Code : %s" % li.read(4))
	idc.ExtLinA(0, 5,  "; CGB Flag : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 6,  "; New Licensee Code : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 7,  "; SGB Flag : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 8,  "; Cartridge Type : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 9,  "; ROM Size : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 10,  "; RAM Size : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 11,  "; Destination Code : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 12,  "; Old license Code : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 13,  "; Mask ROM Version number : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 14,  "; Header Checksum : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 15,  "; Global Checksum : %02X" % struct.unpack("<B", li.read(1))[0])
	idc.ExtLinA(0, 16,  "-------------------------------")

def naming():
	MakeNameEx(0xFF40, "LCD_Control", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF40)
	MakeNameEx(0xFF41, "LCD_Status", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF41)
	MakeNameEx(0xFF42, "SCY", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF42)
	MakeNameEx(0xFF43, "SCX", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF43)
	MakeNameEx(0xFF44, "LY", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF44)
	MakeNameEx(0xFF45, "LYC", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF45)
	MakeNameEx(0xFF4A, "WY", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF4A)
	MakeNameEx(0xFF4B, "WX", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF4B)
	MakeNameEx(0xFF47, "BGP", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF47)	
	MakeNameEx(0xFF48, "OBP0", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF48)
	MakeNameEx(0xFF49, "OBP1", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF49)
	MakeNameEx(0xFF68, "BCPS", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF68)
	MakeNameEx(0xFF69, "BCPD", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF69)
	MakeNameEx(0xFF6A, "OCPS", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF6A)
	MakeNameEx(0xFF6B, "OCPD", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF6B)
	MakeNameEx(0xFF4F, "VBK", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF4F)
	MakeNameEx(0xFF46, "DMA", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF46)
	MakeNameEx(0xFF51, "HDMA1", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF51)
	MakeNameEx(0xFF52, "HDMA2", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF52)
	MakeNameEx(0xFF53, "HDMA3", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF53)
	MakeNameEx(0xFF54, "HDMA4", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF54)
	MakeNameEx(0xFF55, "HDMA5", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF55)
	MakeNameEx(0xFF10, "NR10", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF10)
	MakeNameEx(0xFF11, "NR11", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF11)
	MakeNameEx(0xFF12, "NR12", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF12)
	MakeNameEx(0xFF13, "NR13", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF13)
	MakeNameEx(0xFF14, "NR14", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF14)
	MakeNameEx(0xFF16, "NR21", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF16)
	MakeNameEx(0xFF17, "NR22", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF17)
	MakeNameEx(0xFF18, "NR23", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF18)
	MakeNameEx(0xFF19, "NR24", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF19)
	MakeNameEx(0xFF1A, "NR30", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF1A)
	MakeNameEx(0xFF1B, "NR31", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF1B)
	MakeNameEx(0xFF1C, "NR32", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF1C)
	MakeNameEx(0xFF1D, "NR33", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF1D)
	MakeNameEx(0xFF1E, "NR34", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF1E)
	MakeNameEx(0xFF20, "NR41", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF20)
	MakeNameEx(0xFF21, "NR42", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF21)
	MakeNameEx(0xFF22, "NR43", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF22)
	MakeNameEx(0xFF23, "NR44", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF23)
	MakeNameEx(0xFF24, "NR50", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF24)
	MakeNameEx(0xFF25, "NR51", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF25)
	MakeNameEx(0xFF26, "NR52", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF26)
	MakeNameEx(0xFF00, "JOYP", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF00)
	MakeNameEx(0xFF01, "SB", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF01)
	MakeNameEx(0xFF02, "SC", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF02)
	MakeNameEx(0xFF04, "DIV", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF04)
	MakeNameEx(0xFF05, "TIMA", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF05)
	MakeNameEx(0xFF06, "TMA", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF06)
	MakeNameEx(0xFF07, "TAC", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF07)
	MakeNameEx(0xFFFF, "IE", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFFFF)
	MakeNameEx(0xFF0F, "IF", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF0F)
	MakeNameEx(0xFF4D, "KEY1", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF4D)
	MakeNameEx(0xFF56, "RP", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF56)
	MakeNameEx(0xFF70, "SVBK", SN_NOCHECK | SN_NOWARN)
	MakeByte(0xFF70)


def main():
	return 0
