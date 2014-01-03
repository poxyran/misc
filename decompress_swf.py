# written by poxyran at some point during 2013 :)

import os
import sys
import zlib

from struct import pack
from StringIO import StringIO
from swf.movie import SWF, SWFStream

def read_file(filename):
	fd = open(filename, "rb")
	data = fd.read()
	fd.close()
	return data

def write_file(filename, data):
	fd = open(filename, "wb")
	fd.write(data)
	fd.close()

def rebuild_swf_file(swf_filename, ustream):

	signature = "FWS"
	version = pack("b", 9)

	new_swf_header = signature + version
	filesize = pack("<L", len(ustream)+len(new_swf_header))

	new_swf_file =  new_swf_header + filesize + ustream

	write_file(swf_filename, new_swf_file)

def get_buf(swf_stream_data):
	""" swf_stream_data must be a SWFStream object """
	if not isinstance(swf_stream_data, SWFStream):
		print "[!] The passed parameter is not an SWFStream object"
		return None
	return swf_stream_data.f.buf

def get_data(swf):
	""" swf must be a SWF object """
	if not isinstance(swf, SWF):
		print "[!] The passed parameter is not an SWF object"
		return None
	data = get_buf(swf.data)

	if swf.header.compressed:
		print "[+] Compressed SWF"
		# we skip the first 8-bytes from SWF header
		data = data[8:]
	return data

if len(sys.argv) < 2:
	print "Usage: %s <filename>" % __file__
	sys.exit(0)

swf_filename = sys.argv[1]

raw_data = read_file(swf_filename)
swf_file = SWF(StringIO(raw_data))

data = get_data(swf_file)
ustream = zlib.decompress(data)
filename = os.path.basename(swf_filename) + ".decompressed"
print "[+] Writing new SWF file: %s ..." % filename
rebuild_swf_file(filename, ustream)
print "[+] Done."
