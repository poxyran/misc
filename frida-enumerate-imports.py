import sys
import frida

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

def main(target_process, module_name):
	session = frida.attach(target_process)
	script = session.create_script("""
		Module.enumerateImports("%s", {
			onMatch: function(imp){
				console.log('Module type: ' + imp.type + ' - Name: ' + imp.name + ' - Module: ' + imp.module + ' - Address: ' + imp.address.toString());
			}, 
			onComplete: function(){}
		});
""" % module_name)

	script.on('message', on_message)
	script.load()
	raw_input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 3:
		print 'Usage: %s <process name or PID> <Module Name>' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	main(target_process, sys.argv[2])