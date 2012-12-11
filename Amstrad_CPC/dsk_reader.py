import struct


BYTE = "B"
WORD = "H"

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

def main():
	dskr = DskReader("Lode_Runner.dsk")
	dskr.getdiskinfo()
	dskr.printdiskinfo()
	dskr.printtrackinfo()

if __name__ == "__main__":
    main()
