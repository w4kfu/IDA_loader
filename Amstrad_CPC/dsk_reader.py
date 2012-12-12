import struct

BYTE = "B"
WORD = "H"
DWORD = "I"

DISKINFO = [
	("magic", BYTE * 0x22),		# 0x00-0x21
	("unused1", BYTE * 0x0E),	# 0x22-0x2F
	("tracks", BYTE),		# 0x30
	("sides", BYTE),		# 0x31
	("tracklen", WORD),		# 0x32-0x33
	("unused2", BYTE * 0xCC)	# 0x34-0xFF
	]

SECTORINFO = [
	("track", BYTE),
	("side", BYTE),
	("sectorID", BYTE),
	("sectorSize", BYTE),
	("FDC1", BYTE),
	("FDC2", BYTE),
	("unused1", WORD),
	]

TRACKINFO = [
	("magic", BYTE * 12),		# 0x00-0x0B
	("unused1", BYTE * 0x04),	# 0x0C-0x0F
	("tracknumber", BYTE),		# 0x10
	("sidenumber", BYTE),		# 0x11
	("unused2", WORD),		# 0x12-0x13
	("sectorsize", BYTE),		# 0x14
	("numberofsectors", BYTE),	# 0x15
	("gap", BYTE),			# 0x16
	("fill", BYTE)			# 0x17
	]

DIRENTRY = [
	("user", BYTE),
	("name", BYTE * 8),
	("ext", BYTE * 3),
	("numpage", BYTE),
	("unused", WORD),
	("nbpages", BYTE),
	("blocks", BYTE * 16)
	]

def isprint(c):
	if ord(c) >= 32 and ord(c) <= 126:
		return True
	return False

def hexdump(chars, sep, width):
	offset = 0
	while chars:
		line = chars[:width]
		chars = chars[width:]
		line = line.ljust(width, '\000')
		print("%04X\t%s%s\t%s" % (offset, sep.join("%02x" % ord(c) for c in line),
			sep, quotechars(line)))
		offset += width

def quotechars(chars):
	return ''.join( ['.', c][c.isalnum()] for c in chars )


def extract_str(str, file, endianness):
    	struct_str = endianness + str
    	unpack = struct.unpack(struct_str, file.read(struct.calcsize(struct_str)))
    	if len(unpack) == 1:
        	i, = unpack
        	return i
    	return list(unpack)

def depack(descr, file, endiannes = "<"):
    	struct = dict()
    	for field, value in iter(descr):
        	if isinstance(value, basestring):
            		struct.update({field : extract_str(value, file, endiannes)})
            		continue
        	if isinstance(value, list):
            		struct.update({field : depack(value, file, endiannes)})
            		continue
        	raise DescriptionError("Unhandled type for field : " + field)
    	return struct

class DskReader():

	def __init__(self, filename):
		self.filename = filename
		self.file = open(filename, "rb")
		self.diskinfo = None

	def byte(self, val):
		return struct.pack("<B", val)[0]

	def getdiskinfo(self):
		self.file.seek(0, 0)
		self.diskinfo = depack(DISKINFO, self.file)
		self.nb_track = self.diskinfo['tracks']

	def printdiskinfo(self):
		print(" --- DISK INFO ---")
		print("Filename : %s" % self.filename)
		print("Magic : %s" % ''.join(map(chr, self.diskinfo['magic'])))
		print("Tracks : %d" % self.diskinfo['tracks'])
		print("Sides : %d" % self.diskinfo['sides'])
		print("TrackLen : %d" % self.diskinfo['tracklen'])
	
	def printtrackinfo(self):
		print(" --- TRACK INFO ---")
		self.track = depack(TRACKINFO, self.file)
		print("Magic : %s" % ''.join(map(chr, self.track['magic'])))
		print("Track Number : %d" % self.track['tracknumber'])
		print("Side Number : %d" % self.track['sidenumber'])
		print("Sector Size : %d" % self.track['sectorsize'])
		print("Number of sectors : %d" % self.track['numberofsectors'])
		print("gap : %d" % self.track['gap'])
		print("fill : %d" % self.track['fill'])
		for i in xrange(0, self.track['numberofsectors']):
			print(" --- SECTOR INFO ---")
			self.sector = depack(SECTORINFO, self.file)
			print("track : %d" % self.sector['track'])
			print("side : %d" % self.sector['side'])
			print("SectorID : %d" % self.sector['sectorID'])
			print("SectorSize : %d" % self.sector['sectorSize'])
		self.file.seek(0x100 * 2, 0)
		data = self.file.read(self.sector['sectorSize'] * 0x100)
		hexdump(data, ' ', 16)
		for i in xrange(0, 64):
			self.getinfodirectory(i)

	def getposdata(self, tk, sect, physik):
		Pos = 0x100
		for i in xrange(0, tk + 1):
			self.file.seek(Pos, 0)
			track = depack(TRACKINFO, self.file)
			Pos += 0x100
			for j in xrange(0, track['numberofsectors']):
				sector = depack(SECTORINFO, self.file)
				if i == tk:
					if ((sector['sectorID'] == sect) and physik == 1) or ((j == sect) and physik == 0):
						break
				if sector['sectorSize'] != 0:
					Pos += sector['sectorSize']
				else:
					Pos += (128 << sector['size'])
		return Pos

	def getinfodirectory(self, numdir):
		self.file.seek(((numdir & 15) << 5) + self.getposdata(0, (numdir >> 4) + self.getminsect(), 1), 0)
		directory = depack(DIRENTRY, self.file)
		#if directory['user'] == 0xE5:		# USER_DELETED
		#	return
		# ???
		if directory['numpage'] != 0:
			return
		if self.namevalid(''.join(map(chr, directory['name']))) == False:
			return
		print("User %d" % directory['user'])
		print("Name %s" % self.Nameamsdos(''.join(map(chr, directory['name'])), ''.join(map(chr, directory['ext']))))
		#print("Ext %s" % )
			

	def namevalid(self, name):
		for c in xrange(0, 8):
			if isprint(name[c]) == 0:
				return False
		return True
	
	def getminsect(self):
		self.file.seek(0x100, 0)
		sect = 0x100
		track = depack(TRACKINFO, self.file)
		for i in xrange(0, track['numberofsectors']):
			sector = depack(SECTORINFO, self.file)
			if (sect > sector['sectorID']):
				sect = sector['sectorID']
		return sect

	def Nameamsdos(self, name, ext):
		res = ""
		for c in name:
			if c > ' ' and c != '.':
				res += c
		res += "."
		for i in xrange(0, 3):
			res += ext[i]
		#for i in len(res):
		#	res[i] 
		return res

def main():
	dskr = DskReader("Lode_Runner.dsk")
	dskr.getdiskinfo()
	dskr.printdiskinfo()
	dskr.printtrackinfo()

if __name__ == "__main__":
    main()
