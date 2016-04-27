import sys
import frida

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

def main(target_process, addr, size):
	session = frida.attach(target_process)
	script = session.create_script("""
		var buf = Memory.readByteArray(ptr('0x%x'), %d);
		 console.log(hexdump(buf, {
	 		offset: 0, 
		 		length: %d, 
		 		header: true,
		 		ansi: false
		 	}));
""" % (addr, size, size))

	script.on('message', on_message)
	script.load()
	raw_input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print 'Usage: %s <process name or PID> <addr> <size>' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	addr, size = int(sys.argv[2], 16), int(sys.argv[3])
	main(target_process, addr, size)