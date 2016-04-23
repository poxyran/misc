# written by crackinglandia

from idautils import *
from idaapi import *

print "Enumerating functions..."

ea = BeginEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
	functionName = GetFunctionName(funcea)

	functionStart = GetFunctionAttr(funcea, FUNCATTR_START);
	if functionStart == BADADDR:
		QuitMsg(0, "Could not determine function start!");

	functionEnd = GetFunctionAttr(funcea, FUNCATTR_END)
	if functionEnd == BADADDR:
		QuitMsg(0, "Could not determine function end!");    	

	print "Function Name: %s" % functionName
	print "Function Start: %x - Function End: %x" % (functionStart, functionEnd)
	#print "Function chunks: %r" % Chunks(functionStart)

	functionEnd -= 1
	offset = 0
	while functionStart+offset <= functionEnd:
		MakeComm(functionStart+offset, "offset: %d" % offset)
		print "Getting instruction at: %x" % (functionStart+offset)
		insn = DecodeInstruction(functionStart+offset)
		if insn != None:
			print "Instruction size: %x" % insn.size
			offset += insn.size
		else:
			print "Couldn't get instruction at %x" % (functionStart+offset)
			break
