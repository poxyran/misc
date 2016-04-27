import sys
import frida

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

def make_ba(bytes):
	return '[%s]' % ','.join(["0x%02x" % int(x, 16) for x in bytes.split(' ')])

def main(target_process, addr, bytes):
	session = frida.attach(target_process)
	script = session.create_script("""
		Memory.writeByteArray(ptr('0x%x'), %s);
""" % (addr, bytes))

	script.on('message', on_message)
	script.load()
	raw_input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print 'Usage: %s <process name or PID> <addr> <bytes in the form of "41 42 43 44">' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	addr, bytes = int(sys.argv[2], 16), sys.argv[3]
	
	main(target_process, addr, make_ba(bytes))