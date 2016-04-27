import sys
import frida

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

def main(target_process, pattern):
	session = frida.attach(target_process)
	script = session.create_script("""
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
		var range;

		function processNext(){
			range = ranges.pop();
			if(!range){
				// we are done
				return;
			}

			// due to the lack of blacklisting in Frida, there will be 
			// always an extra match of the given pattern (if found) because
			// the search is done also in the memory owned by Frida.
			Memory.scan(range.base, range.size, '%s', {
				onMatch: function(address, size){
						console.log('[+] Pattern found at: ' + address.toString());
					}, 
				onError: function(reason){
						console.log('[!] There was an error scanning memory');
					}, 
				onComplete: function(){
						processNext();
					}
				});
		}
		processNext();
""" % pattern)

	script.on('message', on_message)
	script.load()
	raw_input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 3:
		print 'Usage: %s <process name or PID> <pattern in form "41 42 ?? 43">' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	pattern = sys.argv[2]
	
	main(target_process, pattern)