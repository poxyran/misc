# written by crackinglandia

import sys
import frida

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

def main(target_process):
	session = frida.attach(target_process)
	script = session.create_script("""
var RtlAllocateHeapAddr = Module.findExportByName('ntdll.dll', 'RtlAllocateHeap');
console.log('RtlAllocateHeap address: ' + RtlAllocateHeapAddr.toString());

var RtlFreeHeapAddr = Module.findExportByName('ntdll.dll', 'RtlFreeHeap');
console.log('RtlFreeHeap address: ' + RtlFreeHeapAddr.toString());

var RtlReAllocateHeapAddr = Module.findExportByName('ntdll.dll', 'RtlReAllocateHeap');
console.log('RtlReAllocateHeap address: ' + RtlReAllocateHeapAddr.toString());

var log_out;

// PVOID RtlAllocateHeap(
//  _In_     PVOID  HeapHandle,
//  _In_opt_ ULONG  Flags,
//  _In_     SIZE_T Size
// );
console.log('>> Hooking ntdll!RtlAllocateHeap...');
Interceptor.attach(RtlAllocateHeapAddr, {
	onEnter: function (args){
		this.log_out = 'RtlAllocateHeap(' + args[0].toString() + ', ' + args[1].toString() + ', ' + args[2].toString();
		//console.log('RtlAllocateHeap(' + args[0].toString() + ', ' + args[1].toString() + ', ' + args[2].toString() + ')');
		//console.log('[+] RtlAllocateHeap called from ' + this.returnAddress.sub(6).toString());
		},
	onLeave: function (retval){
		this.log_out += ') = ' + retval.toString();
		//console.log('RtlAllocateHeap ret value: ' + retval.toString());
		console.log(this.log_out);
		}
	});


// BOOLEAN RtlFreeHeap(
//  _In_     PVOID HeapHandle,
//  _In_opt_ ULONG Flags,
//  _In_     PVOID HeapBase
// );
console.log('>> Hooking ntdll!RtlFreeHeap...');
Interceptor.attach(RtlFreeHeapAddr, {
	onEnter: function(args){
		this.log_out = 'RtlFreeHeap(' + args[0].toString() + ', ' + args[1].toString() + ', ' + args[2].toString(); 
		//console.log('RtlFreeHeap(' + args[0].toString() + ', ' + args[1].toString() + ', ' + args[2].toString() + ')');
		},
	onLeave: function (retval){
		this.log_out += ') = ' + retval.toString();
		console.log(this.log_out);
		//console.log('RtlFreeHeap ret value: ' + retval.toString());
		}
	});


// PVOID RtlReAllocateHeap
// (
//  HANDLE heap,
//  ULONG  flags,
//  PVOID  ptr,
//  SIZE_T size
// )
console.log('>> Hooking ntdll!RtlReAllocateHeap...');
Interceptor.attach(RtlReAllocateHeapAddr, {
	onEnter: function(args){
		this.log_out = 'RtlReAllocateHeap(' + args[0].toString() + ', ' + args[1].toString() + ', ' + args[2].toString() + ', ' + args[3].toString();
		//console.log('RtlReAllocateHeap(' + args[0].toString() + ', ' + args[1].toString() + ', ' + args[2].toString() + ', ' + args[3].toString() + ')');
		},
	onLeave: function (retval){
		this.log_out += ') = ' + retval.toString();
		console.log(this.log_out);
		//console.log('RtlReAllocateHeap ret value: ' + retval.toString());
		}
	})
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