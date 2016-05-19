import sys
import frida

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

def main(target_process):
	session = frida.attach(target_process)
	script = session.create_script("""
function StalkerExeample() 
{
	var threadIds = [];

	Process.enumerateThreads({
		onMatch: function (thread) 
		{
			threadIds.push(thread.id);
			console.log("Thread ID: " + thread.id.toString());
		},

		onComplete: function () 
		{
			threadIds.forEach(function (threadId) 
				{
					Stalker.follow(threadId, 
					{
						events: {call: true},
					
					onReceive: function (events)
					{
						console.log("onReceive called.");
					},
					onCallSummary: function (summary)
					{
						console.log("onCallSummary called.");
					}
				});
			});
		}
	});
}

StalkerExeample();
""")
	script.on('message', on_message)
	script.load()
	raw_input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage: %s <process name or PID>' % __file__
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	main(target_process)
