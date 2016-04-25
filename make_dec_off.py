# written by crackinglandia

from idautils import *
from idaapi import *

print "Enumerating functions..."

ea = BeginEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
        func = get_func(funcea)

	functionName = GetFunctionName(funcea)
	print "Function Name: %s" % functionName
	print "Function Start: %x - Function End: %x" % (func.startEA, func.endEA)

	offset = 0
	while func.startEA+offset <= func.endEA: # '<='? func.endEA is exclusive; IMO it should be '<'
		MakeComm(func.startEA+offset, "%s+%d" % (functionName, offset))
		#print "Getting instruction at: %x" % (functionStart+offset)
		insn = DecodeInstruction(func.startEA+offset)
		if insn != None:
			#print "Instruction size: %x" % insn.size
			offset += insn.size
		else:
			print "Couldn't get instruction at %x" % (func.startEA+offset)
			break

	# handle function chunks
	for chunk in Chunks(func.startEA):
		if chunk[0] != func.startEA:
		        print "Chunk start: %x - end: %x" %(chunk[0], chunk[1])
			dist = abs(chunk[0] - func.startEA)
			chunk_offset = 0
			while chunk[0]+chunk_offset <= chunk[1]:
				MakeComm(chunk[0]+chunk_offset, "(%x+%d)+%d" % (chunk[0], dist, chunk_offset))
				insn = DecodeInstruction(chunk[0]+chunk_offset)
				if insn != None:
					chunk_offset += insn.size
				else:
					print "Couldn't get instruction at %x" %(chunk[0]+chunk_offset)
					break

Message("Done.\n")
