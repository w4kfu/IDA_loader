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
	("size", BYTE),
	("FDC1", BYTE),
	("FDC2", BYTE),
	("SectSize", WORD),
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

STAMSDOS = [
	("usernumber", BYTE),
	("filename", BYTE * 15),
	("blocknum", BYTE),
	("lastblock", BYTE),
	("filetype", BYTE),
	("length", WORD),
	("adress", WORD),
	("firstblock", BYTE),
	("logicallength", WORD),
	("entryadress", WORD),
	("unused", BYTE * 0x24),
	("reallength", WORD),
	("biglength", BYTE),
	("checksum", WORD),
	("unused2", BYTE * 0x3B)
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
			print("Size : %d" % self.sector['size'])
			print("SectorSize : %d" % self.sector['SectSize'])
		self.file.seek(0x100 * 2, 0)
		data = self.file.read(self.sector['size'] * 0x100)
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
				if sector['SectSize'] != 0:
					Pos += sector['SectSize']
				else:
					Pos += (128 << sector['size'])
		return Pos

	def getinfodirectory(self, numdir):
		self.file.seek(((numdir & 15) << 5) + self.getposdata(0, (numdir >> 4) + self.getminsect(), 1), 0)
		directory = depack(DIRENTRY, self.file)
		#if directory['user'] == 0xE5:		# USER_DELETED
		#	return
		if directory['numpage'] != 0:
			return
		if self.namevalid(''.join(map(chr, directory['name']))) == False:
			return
		print("--- New Entry ---")
		print("User %d" % directory['user'])
		print("Name %s" % self.Nameamsdos(''.join(map(chr, directory['name'])), ''.join(map(chr, directory['ext']))))
		print("NumPage %d" % directory['numpage'])
		print("NbPages %d" % directory['nbpages'])
		print("Size %d" % ((directory['nbpages'] + 7 ) >> 3))
		bloc = self.readbloc(directory['blocks'][0])
		#hexdump(bloc, ' ', 16)
		print("Length %X" % struct.unpack(WORD, bloc[24]+bloc[25])[0])
		print("Adress %X" % struct.unpack(WORD, bloc[21]+bloc[22])[0])

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

	def readbloc(self, bloc):
		track = (bloc << 1) / 9
		sect = (bloc << 1) % 9
		minsect = self.getminsect()
		pos = self.getposdata(track, sect + minsect, 1)
		self.file.seek(pos, 0)
		bloc = self.file.read(512)
		sect += 1
		if sect > 8:
			track += 1
			sect = 0
		pos = self.getposdata(track, sect + minsect, 1)
		self.file.seek(pos, 0)
		bloc += self.file.read(512)
		return bloc

	def Nameamsdos(self, name, ext):
		res = ""
		for c in name:
			if c > ' ' and c != '.':
				res += c
		res += "."
		for i in xrange(0, 3):
			res += ext[i]
		return res

def main():
	dskr = DskReader("Lode_Runner.dsk")
	dskr.getdiskinfo()
	dskr.printdiskinfo()
	dskr.printtrackinfo()

if __name__ == "__main__":
    main()
