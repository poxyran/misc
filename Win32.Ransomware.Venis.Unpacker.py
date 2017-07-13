import sys
import pype32
import time

from datetime import datetime
from pype32 import consts
from capstone import *
from capstone.x86_const import *

XOR_KEY = "0xDEADBEEF"
KEY_LEN = 0x0A

def get_imp_function_address(p, func_name):
	impts = p.ntHeaders.optionalHeader.dataDirectory[consts.IMPORT_DIRECTORY]

	func_addr = 0
	indx = 0
	for module in impts.info:
		for iat_entry in module.iat:
			if iat_entry.name.value == func_name:
				func_addr = module.firstThunk + p.ntHeaders.optionalHeader.imageBase + indx * 4
				break
			indx += 1
	return func_addr

def get_xor_data_offset(text_section_code, func_addr):
	offset = -1
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True

	call_found = False
	SIZE = len(text_section_code)
	nop_cnt = 0
	for ins in md.disasm(text_section_code, SIZE):
		if ins.mnemonic == "call" and ins.operands[0].mem.disp == func_addr:
			call_found = True
			call_addr = ins.address

		if call_found and ins.mnemonic == "nop":
			nop_cnt += 1

		if call_found and nop_cnt >= 0x26:
			if ins.address > call_addr:
				if ins.mnemonic == "add" and ins.operands[0].type == X86_OP_REG and (ins.operands[0].reg == X86_REG_ESI or ins.operands[0].reg == X86_REG_EBX) and ins.operands[1].type == X86_OP_IMM:
					offset = ins.operands[1].value.imm.real
					break
	return offset

def write_file(filename, data):
	fd = open(filename, "wb")
	fd.write(data)
	fd.close()

def get_section_data(p, section_name):
	data = ''
	for i in range(len(p.sectionHeaders)):
		if p.sectionHeaders[i].name.value.find(section_name) >= 0:
			data = p.sections[i]
			break
	return data

print "+++ Unpacker for Venis ransomware +++\n"
print "-- written by +NCR/CRC! [ReVeRsEr]"
print "crackinglandia[at]gmail.com\n"

if len(sys.argv) < 2:
	print "Usage: %s <filename>" % __file__
	sys.exit(1)

filename = sys.argv[1]

print "[-] Processing %s" % filename
p = pype32.PE(filename)

print "[-] Getting .text section data..."
text_section_code = get_section_data(p, ".text")
print "[-] Done."

func_name = "SizeofResource"
print "[-] Searching %s function on the IMPORT_DIRECTORY..." % func_name
func_addr = get_imp_function_address(p, func_name)
if func_addr != 0:
	print "[-] %s found at 0x%x" % (func_name, func_addr)
	print "[-] Searching for XORED_DATA_OFFSET value..."
	XORED_DATA_OFFSET = get_xor_data_offset(text_section_code, func_addr)

	if XORED_DATA_OFFSET != -1:
		print "[-] XORED_DATA_OFFSET found: 0x%x" % XORED_DATA_OFFSET

print "[-] Looking for .rsrc section..."
rsrc_section_data = get_section_data(p, ".rsrc")

if rsrc_section_data != '':
	print "[-] .rsrc section found. Starting decryption..."
	print "[-] Searching encrypted data magic value..."
	magic_offset = rsrc_section_data.find("BM6")

	if magic_offset >= 0:
		print "[-] Magic value found at: 0x%x" % magic_offset

		rsrc_section_data = rsrc_section_data[magic_offset+XORED_DATA_OFFSET:]

		data_len = len(rsrc_section_data)
		result = []
		for i in range(data_len):
			b = ord(rsrc_section_data[i]) ^ ord(XOR_KEY[i%KEY_LEN])
			result.append(chr(b))

		d = ''.join(result)
		f = "unpacked_%s_%s.bin" % (datetime.now().strftime('%Y.%m.%d-%H.%M.%S'), filename)
		print "[-] Saving decrypted data to %s" % f
		write_file(f, d)
		print "[+] Done."

"""
References: 
- https://www.arbornetworks.com/blog/asert/mindshare-statically-extracting-malware-c2s-using-capstone-engine/
"""