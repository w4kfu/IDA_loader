from idaapi import *

# TYPE FOR LONG
o_long		= 42

class DecodingError(Exception):
    pass

class m65816_processor_t(idaapi.processor_t):
    	"""
    	Processor module classes must derive from idaapi.processor_t
    	"""
	id = 0
	flag = PR_ADJSEGS | PRN_HEX
    	cnbits = 8
	dnbits = 8
    	psnames = ["65816"]
    	plnames = ["65816 CPU"]
    	segreg_size = 0
    	instruc_start = 0

    	assembler = {
        	"flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              			| AS_NOTAB | AS_ASCIIC | AS_ASCIIZ,
        	"uflag": 0,
        	"name": "65816",
        	"origin": ".org",
        	"end": ".end",
        	"cmnt": ";",
        	"ascsep": '"',
        	"accsep": "'",
        	"esccodes": "\"'",
        	"a_ascii": ".ascii",
        	"a_byte": ".byte",
        	"a_word": ".word",
        	"a_bss": "dfs %s",
        	"a_seg": "seg",
        	"a_curip": "PC",
        	"a_public": "",
        	"a_weak": "",
        	"a_extrn": ".extern",
        	"a_comdef": "",
        	"a_align": ".align",
        	"lbrace": "(",
        	"rbrace": ")",
        	"a_mod": "%",
        	"a_band": "&",
        	"a_bor": "|",
        	"a_xor": "^",
        	"a_bnot": "~",
        	"a_shl": "<<",
        	"a_shr": ">>",
        	"a_sizeof_fmt": "size %s",
    		}

	reg_names = regNames = [
		"A", 		# Accumulator
		"X", "Y", 	# Index
		"S", 		# Stack Pointer
		"DRB", "DB",	# Data Bank
		"D", "DP",	# Direct Page
		"PB", "PBR", 	# Program Bank
		"P",		# Process Status
		"PC",		# Program Counter
            	# Fake segment registers
            	"CS",
            	"DS"
		]

    	instruc = instrs = [
		# ADC
		{'name': 'addc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Adds operand to the Accumulator; adds an additional 1 if carry is set."},
		# AND
		{'name': 'and',  'feature': CF_USE1 | CF_USE2, 'cmt': "The operand is \"AND\"ed to the Accumulator."},
		# ASL
		{'name': 'asl',  'feature': CF_USE1 | CF_USE2, 'cmt': "Performs a shift left."},
		# BCC
		{'name': 'bcc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Jump to a new location within the -128 to 127 range if the carry flag is clear."},
		# BCS
		{'name': 'bcs',  'feature': CF_USE1 | CF_USE2, 'cmt': "Jump to a new location within the -128 to 127 range if the carry flag is set."},
		# BEQ
		{'name': 'beq',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches is zero flag is set."},
		# BIT
		{'name': 'bit',  'feature': CF_USE1 | CF_USE2, 'cmt': "Performs AND except only the flags are modified."},
		# BMI
		{'name': 'bmi',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches if negative flag is set."},
		# BNE
		{'name': 'bne',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches if zero flag clear."},
		# BPL
		{'name': 'bpl',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches if negative flag clear."},
		# BRA
		{'name': 'bra',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches always."},
		# BRK
		{'name': 'brk',  'feature': CF_STOP, 'cmt': "Causes a software break. The PC is loaded from a vector table from somewhere around $FFE6."},
		# BRL
		{'name': 'brl',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branch Relative Long."},
		# BVC
		{'name': 'bvc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches if overflow flag is clear."},
		# BVS
		{'name': 'bvs',  'feature': CF_USE1 | CF_USE2, 'cmt': "Branches if overflow flag is set."},
		# CLC
		{'name': 'clc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Clears the carry flag."},
		# CLD
		{'name': 'cld',  'feature': CF_USE1 | CF_USE2, 'cmt': "Clears the decimal flag."},
		# CLI
		{'name': 'cli',  'feature': CF_USE1 | CF_USE2, 'cmt': "Clears the interrupt Flag."},
		# CLV
		{'name': 'clv',  'feature': CF_USE1 | CF_USE2, 'cmt': "Clears the overflow Flag."},
		# CMP
		{'name': 'cmp',  'feature': CF_USE1 | CF_USE2, 'cmt': "Compare accumulator with memory."},
		# CPX
		{'name': 'cpx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Compare X with memory"},
		# CPY
		{'name': 'cpy',  'feature': CF_USE1, 'cmt': "Compare Y with memory"},
		# COP
		{'name': 'cop',  'feature': 0, 'cmt': "Causes a software interrupt using a vector."},
		# DEC
		{'name': 'dec',  'feature': CF_USE1 | CF_USE2, 'cmt': "Decrement accumulator"},
		# DEX
		{'name': 'dex',  'feature': CF_USE1 | CF_USE2, 'cmt': "Decrement X"},
		# DEY
		{'name': 'dey',  'feature': CF_USE1 | CF_USE2, 'cmt': "Decrement Y"},
		# EOR
		{'name': 'eor',  'feature': CF_USE1 | CF_USE2, 'cmt': "Exclusive OR accumulator"},
		# INC
		{'name': 'inc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Increment accumulator"},
		# INX
		{'name': 'inx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Increment X"},
		# INY
		{'name': 'iny',  'feature': CF_USE1 | CF_USE2, 'cmt': "Increment Y"},
		# JMP
		{'name': 'jmp',  'feature': CF_USE1, 'cmt': "Jump to location"},
		# JML
		{'name': 'jml',  'feature': CF_USE1 | CF_USE2, 'cmt': "Jump long"},
		# JSR
		{'name': 'jsr',  'feature': CF_USE1, 'cmt': "Jump subroutine"},
		# JSL
		{'name': 'jsl',  'feature': CF_USE1 | CF_USE2, 'cmt': "Jump subroutine long"},
		# LDA
		{'name': 'lda',  'feature': CF_USE1 | CF_USE2, 'cmt': "Load Accumulator with memory"},
		# LDX
		{'name': 'ldx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Load X with memory"},
		# LDY
		{'name': 'ldy',  'feature': CF_USE1 | CF_USE2, 'cmt': "Load Y with memory"},
		# LSR
		{'name': 'lsr',  'feature': CF_USE1 | CF_USE2, 'cmt': "Shift Right Accumulator, Memory"},
		# MVN
		{'name': 'mvn',  'feature': CF_USE1 | CF_USE2, 'cmt': "Block move negative"},
		# MVP
		{'name': 'mvp',  'feature': CF_USE1 | CF_USE2, 'cmt': "Block move positive"},
		# NOP
		{'name': 'nop',  'feature': CF_USE1 | CF_USE2, 'cmt': "No operation"},
		# ORA
		{'name': 'ora',  'feature': CF_USE1 | CF_USE2, 'cmt': "\"OR\" accumulator with memory"},
		# PEA
		{'name': 'pea',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push effective Address"},
		# PEI
		{'name': 'pei',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push effective Indirect Address"},
		# PER
		{'name': 'per',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push Program Counter Relative"},
		# PHA
		{'name': 'pha',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push accumulator"},
		# PHD
		{'name': 'phd',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push Direct Page Register"},
		# PHK
		{'name': 'phk',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push Program Bank"},
		# PHX
		{'name': 'phx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Push X"},
		# PHY
		{'name': 'phy',  'feature': 0, 'cmt': "Push Y"},
		# PLA
		{'name': 'pla',  'feature': CF_USE1 | CF_USE2, 'cmt': "Pull accumulator"},
		# PLD
		{'name': 'pld',  'feature': CF_USE1 | CF_USE2, 'cmt': "Pull Direct Page Register"},
		# PLP
		{'name': 'plp',  'feature': CF_USE1 | CF_USE2, 'cmt': "Pull Flags"},
		# PLX
		{'name': 'plx',  'feature': 0, 'cmt': "Pull X"},
		# PLY
		{'name': 'ply',  'feature': CF_USE1 | CF_USE2, 'cmt': "Pull Y"},
		# REP
		{'name': 'rep',  'feature': CF_USE1 | CF_USE2, 'cmt': "Reset Flag"},
		# ROL
		{'name': 'rol',  'feature': CF_USE1 | CF_USE2, 'cmt': "Rotate bit left"},
		# ROR
		{'name': 'ror',  'feature': CF_USE1 | CF_USE2, 'cmt': "Rotate bit right"},
		# RTI
		{'name': 'rti',  'feature': CF_STOP, 'cmt': "Return from Interupt"},
		# RTS
		{'name': 'rts',  'feature': CF_USE1 | CF_USE2, 'cmt': "Return from Subroutine"},
		# RTL
		{'name': 'rtl',  'feature': CF_USE1 | CF_USE2, 'cmt': "Return from Subroutine long"},
		# SBC
		{'name': 'sbc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Substract with carry"},
		# SEC
		{'name': 'sec',  'feature': 0, 'cmt': "Set carry flag"},
		# SED
		{'name': 'sed',  'feature': CF_USE1 | CF_USE2, 'cmt': "Set decimal flag"},
		# SEI
		{'name': 'sei',  'feature': CF_USE1 | CF_USE2, 'cmt': "Set Interrupt flag"},
		# SEP
		{'name': 'sep',  'feature': CF_USE1 | CF_USE2, 'cmt': "Set flag"},
		# STA
		{'name': 'sta',  'feature': CF_USE1 | CF_USE2, 'cmt': "Store accumulator to memory"},
		# STX
		{'name': 'stx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Store X to memory"},
		# STY
		{'name': 'sty',  'feature': CF_USE1 | CF_USE2, 'cmt': "Store Y to memory"},
		# STP
		{'name': 'stp',  'feature': CF_USE1 | CF_USE2, 'cmt': "Stop the clock"},
		# STZ
		{'name': 'stz',  'feature': CF_USE1 | CF_USE2, 'cmt': "Stop zero to memory"},
		# TAX
		{'name': 'tax',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer accumulator to X"},
		# TAY
		{'name': 'tay',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer accumulator to Y"},
		# TCD
		{'name': 'tcd',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Accumulator to Direct Page"},
		# TCS
		{'name': 'tcs',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Accumulator to Stack"},
		# TDC
		{'name': 'tdc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Direct Page to Accumulator"},
		# TSC
		{'name': 'tsc',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Stack to Accumulator"},
		# TSX
		{'name': 'tsx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Stack to X"},
		# TXA
		{'name': 'txa',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer X to Accumulator"},
		# TXS
		{'name': 'txs',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer X to Stack"},
		# TXY
		{'name': 'txy',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer X to Y"},
		# TYA
		{'name': 'tya',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Y to accumulator"},
		# TYX
		{'name': 'tyx',  'feature': CF_USE1 | CF_USE2, 'cmt': "Transfer Y to X"},
		# TRB
		{'name': 'trb',  'feature': CF_USE1 | CF_USE2, 'cmt': "Test and Reset bit"},
		# TSB
		{'name': 'tsb',  'feature': CF_USE1, 'cmt': "Test and set bit"},
		# WAI
		{'name': 'wai',  'feature': 0, 'cmt': "Wait for Interupt"},
		# XCE
		{'name': 'xce',  'feature': CF_USE1 | CF_USE2, 'cmt': "Exchange Carry with emulation"}
		]
    	instruc_end = len(instruc)

	def __init__(self):
		processor_t.__init__(self)
		self._init_instructions()
		self._init_registers()

	def _init_instructions(self):
		self.inames = {}
		for idx, ins in enumerate(self.instrs):
	    		self.inames[ins['name']] = idx

	def _init_registers(self):
		self.reg_ids = {}
		for i, reg in enumerate(self.reg_names):
	    		self.reg_ids[reg] = i
        	self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        	self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]


	def _read_cmd_byte(self):
        	ea = self.cmd.ea + self.cmd.size
        	byte = get_full_byte(ea)
        	self.cmd.size += 1
        	return byte

	def _read_cmd_word(self):
        	ea = self.cmd.ea + self.cmd.size
        	byte = get_full_byte(ea)
		byte |= get_full_byte(ea) << 8
        	self.cmd.size += 2		
        	return byte

	def _read_cmd_lword(self):
        	ea = self.cmd.ea + self.cmd.size
        	byte = get_full_byte(ea)
		byte |= get_full_byte(ea) << 8
		byte |= get_full_byte(ea) << 16
        	self.cmd.size += 3
        	return byte

	def u8_to_s8(self, n):
		if (n & 0x80):
			return n - 0x100
		return n

	def handle_dp_indexed_indirect_X(self):
		cmd = self.cmd
		cmd[0].type = o_displ
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[0].reg = 1
		cmd[1].type = o_void

	def handle_stack_relative(self):
		cmd = self.cmd
		cmd[0].type = o_imm
		cmd[0].dtype = dt_byte
		cmd[0].value = self._read_cmd_byte()
		cmd[1].type = o_reg
		cmd[1].reg = 3

	def handle_direct_page(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[1].type = o_void

	def handle_dp_indirect_long(self):
		cmd = self.cmd
		cmd[0].type = o_long
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[1].type = o_void

	def handle_immediate(self):
		cmd = self.cmd
		cmd[0].type = o_imm
		cmd[0].dtype = dt_byte
		cmd[0].value = self._read_cmd_byte()
		cmd[1].type = o_void

	def handle_absolute(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_word
		cmd[0].addr = self._read_cmd_word()
		cmd[1].type = o_void

	def handle_absolute_long(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_dword
		cmd[0].addr = self._read_cmd_lword()
		cmd[1].type = o_void
	
	def handle_dp_indirect_indexed_Y(self):
		cmd = self.cmd
		cmd[0].type = o_phrase
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[0].reg = -1
		cmd[1].type = o_reg
		cmd[1].reg = 2

	def handle_dp_indirect(self):
		cmd = self.cmd
		cmd[0].type = o_phrase
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[0].reg = -1
		cmd[1].type = o_void

	def handle_stack_relative_indirect_indexed_Y(self):
		cmd = self.cmd
		cmd[0].type = o_displ
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[0].reg = 3
		cmd[1].type = o_reg
		cmd[1].reg = 2

	def handle_dp_indexed_X(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[1].type = o_reg
		cmd[1].reg = 1

	def handle_dp_indirect_long_indexed_Y(self):
		cmd = self.cmd
		cmd[0].type = o_long
		cmd[0].dtype = dt_byte
		cmd[0].addr = self._read_cmd_byte()
		cmd[1].type = o_reg
		cmd[1].reg = 2

	def handle_absolute_indexed_Y(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_word
		cmd[0].addr = self._read_cmd_word()
		cmd[1].type = o_reg
		cmd[1].reg = 2

	def handle_absolute_indexed_X(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_word
		cmd[0].addr = self._read_cmd_word()
		cmd[1].type = o_reg
		cmd[1].reg = 1

	def handle_accumulator(self):
		cmd = self.cmd
		cmd[0].type = o_reg
		cmd[0].reg = 0
		cmd[1].type = o_void
		
	def handle_absolute_long_indexed_X(self):
		cmd = self.cmd
		cmd[0].type = o_mem
		cmd[0].dtype = dt_dword
		cmd[0].addr = self._read_cmd_lword()
		cmd[1].type = o_reg
		cmd[1].reg = 1

	def handle_absolute_indirect(self):
		cmd = self.cmd
		cmd[0].type = o_phrase
		cmd[0].dtype = dt_word
		cmd[0].addr = self._read_cmd_word()
		cmd[0].reg = 0xFFFF

	def handle_absolute_indexed_indirect(self):
		cmd = self.cmd
		cmd[0].type = o_displ
		cmd[0].dtype = dt_word
		cmd[0].addr = self._read_cmd_word()
		cmd[0].reg = 1
	
	def handle_absolute_indirect_long(self):
		self.handle_absolute_indirect()

	def handle_type(self, opcode):
		table_handle = [
				self.handle_immediate, 				# 0x00 TO CHECK !
				self.handle_dp_indexed_indirect_X, 		# 0x01
				self.handle_immediate, 				# 0x02 TO CHECK !
				self.handle_stack_relative, 			# 0x03
				self.handle_direct_page, 			# 0x04 TO CHECK !
				self.handle_direct_page, 			# 0x05
				self.handle_direct_page, 			# 0x06 TO CHECK !
				self.handle_dp_indirect_long, 			# 0x07
				0,						# 0x08
				self.handle_immediate,				# 0x09
				self.handle_accumulator,			# 0x0A
				0,						# 0x0B
				self.handle_absolute,				# 0x0C
				self.handle_absolute,				# 0x0D
				self.handle_absolute,				# 0x0E TO CHECK !
				self.handle_absolute_long,			# 0x0F
				0,						# 0x10
				self.handle_dp_indirect_indexed_Y,		# 0x11
				self.handle_dp_indirect,			# 0x12
				self.handle_stack_relative_indirect_indexed_Y,	# 0x13
				self.handle_dp_indexed_X,			# 0x14 TO CHECK !
				self.handle_dp_indexed_X,			# 0x15
				self.handle_dp_indexed_X,			# 0x16 TO CHECK !
				self.handle_dp_indirect_long_indexed_Y,		# 0x17
				0,						# 0x18
				self.handle_absolute_indexed_Y,			# 0x19
				self.handle_accumulator,			# 0x1A TO CHECK !
				0,						# 0x1B
				self.handle_absolute_indexed_X,			# 0x1C
				self.handle_absolute_indexed_X,			# 0x1D
				self.handle_absolute_indexed_X,			# 0x1E TO CHECK !
				self.handle_absolute_long_indexed_X		# 0x1F
				]
		table_handle[opcode & 0x1F]()

	def handle_branch(self):
		cmd[0].type = o_near
		cmd[0].dtype = dt_byte
		cmd[0].addr = self.cmd.ea + self.u8_to_s8(self._read_cmd_byte()) + 2

	def handle_jump(self, opcode):
		if opcode == 0x4C:
			self.handle_absolute()
		elif opcode == 0x5C:
			self.handle_absolute_long()
		elif opcode == 0x6C:
			self.handle_absolute_indirect()
		elif opcode == 0x7C:
			self.handle_absolute_indexed_indirect()
		elif opcode == 0xDC:
			self.handle_absolute_indirect_long()

	def handle_jsr(self, opcode):
		if opcode == 0x20:
			self.handle_absolute()
		elif opcode == 0x22:
			self.handle_absolute_long()
		elif opcode == 0xFC:
			self.handle_absolute_indexed_indirect()

	def handle_push_pull(self, opcode, reg):
		cmd[0].type = o_reg
		cmd[0].reg = reg

    	def _ana(self):
		cmd = self.cmd
		opcode = self._read_cmd_byte()
		# ADC
		if opcode in [0x61, 0x63, 0x65, 0x67, 0x69, 0x6D, 0x6F, 0x71, 0x72, 0x73, 0x75, 0x77, 0x79, 0x7D, 0x7F]:
			cmd.itype = self.inames["adc"]
			self.handle_type(opcode)
		# AND
		elif opcode in [0x21, 0x23, 0x25, 0x27, 0x29, 0x2D, 0x2F, 0x31, 0x32, 0x33, 0x35, 0x37, 0x39, 0x3D, 0x3F]:
			cmd.itype = self.inames["and"]
			self.handle_type(opcode)
		# ASL
		elif opcode in [0x06, 0x0A, 0x0E, 0x16, 0x1E]:
			cmd.itype = self.inames["asl"]
			self.handle_type(opcode)
		# BIT
		elif opcode in [0x24, 0x2C, 0x34, 0x3C, 0x89]:
			cmd.itype = self.inames["bit"]
			self.handle_type(opcode)
		# BCC
		elif opcode == 0x90:
			cmd.itype = self.inames["bcc"]
			self.handle_branch()
		# BCS
		elif opcode == 0xB0:
			cmd.itype = self.inames["bcs"]
			self.handle_branch()
		# BEQ
		elif opcode == 0xF0:
			cmd.itype = self.inames["beq"]
			self.handle_branch()
		# BMI
		elif opcode == 0x30:
			cmd.itype = self.inames["bmi"]
			self.handle_branch()
		# BNE
		elif opcode == 0xD0:
			cmd.itype = self.inames["bne"]
			self.handle_branch()
		# BPL
		elif opcode == 0x10:
			cmd.itype = self.inames["bpl"]
			self.handle_branch()
		# BRA
		elif opcode == 0x80:
			cmd.itype = self.inames["bra"]
			self.handle_branch()
		# BRK
		elif opcode == 0x00:
			cmd.itype = self.inames["brk"]
		# BVC
		elif opcode == 0x50:
			cmd.itype = self.inames["bvc"]
			self.handle_branch()
		# BVS
		elif opcode == 0x70:
			cmd.itype = self.inames["bvs"]
			self.handle_branch()
		# CLC
		elif opcode == 0x18:
			cmd.itype = self.inames["clc"]
		# CLD
		elif opcode == 0xD8:
			cmd.itype = self.inames["cld"]
		# CLI
		elif opcode == 0x58:
			cmd.itype = self.inames["cli"]
		# CLV
		elif opcode == 0xB8:
			cmd.itype = self.inames["clv"]
		# CMP
		elif opcode in [0xC1, 0xC3, 0xC5, 0xC7, 0xC9, 0xCD, 0xCF, 0xD1, 0xD2, 0xD3, 0xD5, 0xD7, 0xD9, 0xDD, 0xDF]:
			cmd.itype = self.inames["cmp"]
			self.handle_type(opcode)
		# COP
		elif opcode == 0x02:
			cmd.itype = self.inames["cop"]
			cmd[0].type = o_imm
			cmd[0].dtyp = dt_byte
			cmd[0].value = self._read_cmd_byte()
		# CPX
		elif opcode in [0xE0, 0xE4, 0xEC]:
			cmd.itype = self.inames["cpx"]
			self.handle_type(opcode)
		# CPY
		elif opcode in [0xC0, 0xC4, 0xCC]:
			cmd.itype = self.inames["cpy"]
			self.handle_type(opcode)
		# DEC
		elif opcode in [0x3A, 0xC6, 0xCE, 0xD6, 0xDE]:
			cmd.itype = self.inames["dec"]
			self.handle_dec(opcode)
		# DEX
		elif opcode == 0xCA:
			cmd.itype = self.inames["dex"]
		# DEY
		elif opcode == 0x88:
			cmd.itype = self.inames["dey"]
		# EOR
		elif opcode in [0x41, 0x43, 0x45, 0x47, 0x49, 0x4D, 0x4F, 0x51, 0x52, 0x53, 0x55, 0x57, 0x59, 0x5D, 0x5F]:
			cmd.itype = self.inames["eor"]
			seld.handle_type(opcode)
		# INC
		elif opcode in [0x1A, 0xE6, 0xEE, 0xF6, 0xFE]:
			cmd.itype = self.inames["inc"]
		# INX
		elif opcode == 0xE8:
			cmd.itype = self.inames["inx"]
		# INY
		elif opcode == 0xC8:
			cmd.itye = self.inames["iny"]
		# JML
		elif ocpode in [0xDC]:
			cmd.itype = self.inames["jml"]
			self.handle_jump(opcode)
		# JMP
		elif opcode in [0x4C, 0x5C, 0x6C, 0x7C, 0xDC]:
			cmd.itype = self.inames["jmp"]
			self.handle_jump(opcode)
		# JSL
		elif  opcode == 0x22:
			cmd.itype = self.inames["jsl"]
		# JSR
		elif opcode in [0x20, 0xFC]:
			cmd.itype = self.inames["jsr"]
			self.handle_jsr(opcode)
		# LDA
		elif opcode in [0xA1, 0xA3, 0xA5, 0xA7, 0xA9, 0xAD, 0xAF, 0xB1, 0xB2, 0xB3, 0xB5, 0xB7, 0xB9, 0xBD, 0xBF]:
			cmd.itype = self.inames["lda"]
			self.handle_type(opcode)
		# LDX
		elif opcode in [0xA2, 0xA6, 0xAE, 0xB6, 0xBE]:
			cmd.itype = self.inames["ldx"]
			self.handle_type(opcode)
		# LDY
		elif opcode in [0xA0, 0xA4, 0xAC, 0xB4, 0xBC]:
			cmd.itype = self.inames["ldy"]
			self.handle_type(opcode)
		# LSR
		elif opcode in [0x46, 0x4A, 0x4E, 0x56, 0x5E]:
			cmd.itype = self.inames["lsr"]
			self.handle_type(opcode)
		# MVN
		elif opcode == 0x54:
			cmd.itype = self.inames["mvn"]
			cmd[0].type = o_mem
			cmd[0].dtyp = dt_byte
			cmd[0].addr = self._read_cmd_byte()
			cmd[1].type = o_mem
			cmd[1].dtyp = dt_byte
			cmd[1].addr = self._read_cmd_byte()
		# MVS
		elif opcode == 0x54:
			cmd.itype = self.inames["mvs"]
			cmd[0].type = o_mem
			cmd[0].dtyp = dt_byte
			cmd[0].addr = self._read_cmd_byte()
			cmd[1].type = o_mem
			cmd[1].dtyp = dt_byte
			cmd[1].addr = self._read_cmd_byte()
		# NOP
		elif opcode == 0xEA:
			cmd.itype = self.inames["nop"]
		# ORA
		elif opcode in [0x01, 0x03, 0x05, 0x07, 0x09, 0x0D, 0x0F, 0x11, 0x12, 0x13, 0x15, 0x17, 0x19, 0x1D, 0x1F]:
			cmd.itype = self.inames["ora"]
			self.handle_type(opcode)
		# PEA
		elif opcode == 0xF4:
			cmd.itype = self.inames["pea"]
			cmd[0].type = o_mem
			cmd[0].dtype = dt_word
			cmd[0].addr = self._read_cmd_word()
		# PEI
		elif opcode == 0xD4:
			cmd.itype = self.inames["pei"]
			cmd[0].type = o_phrase
			cmd[0].dtype = dt_byte
			cmd[0].addr = self._read_cmd_byte()
			cmd[0].reg = -1
		# PHA
		elif opcode == 0x48:
			cmd.itype = self.inames["pha"]
			self.handle_push_pull(opcode, 0)
		# PHB
		elif opcode == 0x8B:
			cmd.itype = self.inames["phb"]
			self.handle_push_pull(opcode, 4)
		# PHD
		elif opcode == 0x0B:
			cmd.itype = self.inames["phd"]
			self.handle_push_pull(opcode, 7)
		# PHK
		elif opcode == 0x4B:
			cmd.itype = self.inames["phk"]
			self.handle_push_pull(opcode, 9)
		# PHP
		elif opcode == 0x08:
			cmd.itype = self.inames["php"]
			self.handle_push_pull(opcode, 10)
		# PHX
		elif opcode == 0xDA:
			cmd.itype = self.inames["phx"]
			self.handle_push_pull(opcode, 1)
		# PHY
		elif opcode == 0x5A:
			cmd.itype = self.inames["phy"]
			self.handle_push_pull(opcode, 2)
		# PLA
		elif opcode == 0x68:
			cmd.itype = self.inames["pla"]
			self.handle_push_pull(opcode, 0)
		# PLB
		elif opcode == 0xAB:
			cmd.itype = self.inames["plb"]
			self.handle_push_pull(opcode, 4)
		# PLD
		elif opcode == 0x2B:
			cmd.itype = self.inames["pld"]
			self.handle_push_pull(opcode, 7)
		# PLP
		elif opcode == 0x28:
			cmd.itype = self.inames["plp"]
			self.handle_push_pull(opcode, 10)
		# PLX
		elif opcode == 0xFA:
			cmd.itype = self.inames["plx"]
			self.handle_push_pull(opcode, 1)	
		# PLY
		elif opcode == 0x7A:
			cmd.itype = self.inames["ply"]
			self.handle_push_pull(opcode, 2)
		# REP
		elif opcode == 0xC2:
			cmd.itype = self.inames["rep"]
			self.handle_type(opcode)
		# ROL
		elif opcode in [0x26, 0x2A, 0x2E, 0x36, 0x3E]:
			cmd.itype = self.inames["rol"]
			self.handle_type(opcode)
		# ROR
		elif opcode in [0x66, 0x6A, 0x6E, 0x76, 0x7E]:
			cmd.itype = self.inames["ror"]
			self.handle_type(opcode)
		# RTI
		elif opcode == 0x40:
			cmd.itype = self.inames["rti"]
		# RTL
		elif opcode == 0x6B:
			cmd.itype = self.inames["rtl"]
		# RTS
		elif opcode == 0x60:
			cmd.itype = self.inames["rts"]
		# SBC
		elif opcode in [0xE1, 0xE3, 0xE5, 0xE7, 0xE9, 0xED, 0xEF, 0xF1, 0xF2, 0xF3, 0xF5, 0xF7, 0xF9, 0xFD, 0xFF]:
			cmd.itype = self.inames["sbc"]
			self.handle_type(opcode)
		# SEC
		elif opcode == 0x38:
			cmd.itype = self.inames["sec"]
		# SEI
		elif opcode == 0xF8:
			cmd.itype = self.inames["sei"]
		# SEP
		elif opcode == 0xE2:
			cmd.itype = self.inames["sep"]
		# STA 
		elif opcode in [0x81, 0x83, 0x85, 0x87, 0x8D, 0x8F, 0x91, 0x92, 0x93, 0x95, 0x97, 0x99, 0x9D, 0x9F]:
			cmd.itype = self.inames["sta"]
			self.handle_type(opcode)
		# STP
		elif opcode == 0xDB:
			cmd.itype = self.inames["stp"]
		# STX
		elif opcode in [0x86, 0x8E, 0x96]:
			cmd.itype = self.inames["stx"]
			self.handle_type(opcode)
		# STY
		elif opcode in [0x84, 0x8C, 0x94]:
			cmd.itype = self.inames["sty"]
			self.handle_type(opcode)
		# STZ
		elif opcode in [0x64, 0x74, 0x9C, 0x9E]:
			cmd.itype = self.inames["stz"]
			self.handle_type(opcode)
		# TAX
		elif opcode == 0xAA:
			cmd.itype = self.inames["tax"]
		# TAY
		elif opcode == 0xA8:
			cmd.itype = self.inames["tay"]
		# TCD
		elif opcode == 0x5B:
			cmd.itype = self.inames["tcd"]
		# TCS
		elif opcode == 0x1B:
			cmd.itype = self.inames["tcs"]
		# TDC
		elif opcode == 0x7B:
			cmd.itype = self.inames["tdc"]
		# TRB
		elif opcode in [0x14, 0x1C]:
			cmd.itype = self.inames["trb"]
			self.handle_type(opcode)
		# TSB
		elif opcode in [0x04, 0x0C]:
			cmd.itype = self.inames["tsb"]
			self.handle_type(opcode)
		# TSC
		elif opcode == 0x3B:
			cmd.itype = self.inames["tsc"]
		# TSX
		elif opcode == 0xBA:
			cmd.itype = self.inames["tsx"]
		# TXA
		elif opcode == 0x8A:
			cmd.itype = self.inames["txa"]
		# TXS
		elif opcode == 0x9A:
			cmd.itype = self.inames["txs"]
		# TXY
		elif opcode == 0x9B:
			cmd.itype = self.inames["txy"]
		# TYA
		elif opcode == 0x98:
			cmd.itype = self.inames["tya"]
		# TYX
		elif opcode == 0xBB:
			cmd.itype = self.inames["tyx"]
		# WAI
		elif opcode == 0xCB:
			cmd.itype = self.inames["wai"]
		# WDM
		elif opcode == 0x42:
			cmd.itype = self.inames["wdm"]
			self._read_cmd_byte()
		# XBA
		elif opcode == 0xEB:
			cmd.itype = self.inames["xba"]
		# XCE
		elif opcode == 0xFB:
			cmd.itype = self.inames["xce"]
		else:
			raise DecodingError()
		return cmd.size

    	def ana(self):
        	try:
            		return self._ana()
        	except DecodingError:
			return 0

	def _emu_operand(self, op):
		if op.type == o_mem:
			ua_dodata2(0, op.addr, op.dtyp)
			ua_add_dref(0, op.addr, dr_R)
        	elif op.type == o_near:
            		if self.cmd.get_canon_feature() & CF_CALL:
                		fl = fl_CN
            		else:
                		fl = fl_JN
            		ua_add_cref(0, op.addr, fl)

    	def emu(self):
        	cmd = self.cmd
        	ft = cmd.get_canon_feature()
        	if ft & CF_USE1:
            		self._emu_operand(cmd[0])
        	if ft & CF_USE2:
            		self._emu_operand(cmd[1])
        	if ft & CF_USE3:
            		self._emu_operand(cmd[2])
        	if not ft & CF_STOP:
            		ua_add_cref(0, cmd.ea + cmd.size, fl_F)
        	return True

	def outop(self, op):
		if op.type == o_reg:
            		out_register(self.reg_names[op.reg])
        	elif op.type == o_imm:
            		out_symbol('#')
            		OutValue(op, OOFW_IMM)
        	elif op.type in [o_near, o_mem]:
            		ok = out_name_expr(op, op.addr, BADADDR)
            		if not ok:
                		out_tagon(COLOR_ERROR)
                		OutLong(op.addr, 16)
                		out_tagoff(COLOR_ERROR)
                		QueueMark(Q_noName, self.cmd.ea)
        	elif op.type == o_phrase:
            		out_symbol('(')
			if op.reg == 0xFFFF:
				ok = out_name_expr(op, op.addr, BADADDR)
            			if not ok:
                			out_tagon(COLOR_ERROR)
                			OutLong(op.addr, 16)
                			out_tagoff(COLOR_ERROR)
                			QueueMark(Q_noName, self.cmd.ea)
			else:
            			out_register(self.reg_names[op.reg])
            		out_symbol(')')
        	elif op.type == o_displ:
            		out_symbol('(')
            		ok = out_name_expr(op, op.addr, BADADDR)
			if not ok:
				out_tagon(COLOR_ERROR)
				OutLong(op.addr, 16)
				out_tagoff(COLOR_ERROR)
				QueueMark(Q_noName, self.cmd.ea)
            		out_symbol(',')
            		out_symbol(' ')
            		out_register(self.reg_names[op.reg])
            		out_symbol(')')
		elif op.type == o_long:
            		out_symbol('[')
            		ok = out_name_expr(op, op.addr, BADADDR)
			if not ok:
				out_tagon(COLOR_ERROR)
				OutLong(op.addr, 16)
				out_tagoff(COLOR_ERROR)
				QueueMark(Q_noName, self.cmd.ea)
            		out_symbol(']')
        	else:
            		return False
        	return True

    	def out(self):
        	cmd = self.cmd
        	ft = cmd.get_canon_feature()
        	buf = init_output_buffer(1024)
        	OutMnem(15)
        	if ft & CF_USE1:
            		out_one_operand(0)
        	if ft & CF_USE2:
			if self.cmd[1].type != o_void:
            			OutChar(',')
            			OutChar(' ')
            			out_one_operand(1)
        	term_output_buffer()
        	cvar.gl_comm = 1
        	MakeLine(buf)



def PROCESSOR_ENTRY():
    return m65816_processor_t()	

