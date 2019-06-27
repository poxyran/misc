from __future__ import print_function

import idaapi
import idautils
import idc

# http://moritzraabe.de/2017/01/15/ida-pro-anti-disassembly-basic-blocks-and-idapython/

# This script counts the number of basic blocks present in a function recognized by the auto-analysis of IDA
def main():
    data = []
    for fva in idautils.Functions():
        func_name = GetFunctionName(fva)
        function = idaapi.get_func(fva)
        func_start_addr = function.startEA
        flowchart = idaapi.FlowChart(function)
        #print ("[-] Function name: %s, Start addr: %x, no. basic blocks: %d" % (func_name, func_start_addr, flowchart.size))
        data.append("[-] Function name: %s, Start addr: %x, no. basic blocks: %d" % (func_name, func_start_addr, flowchart.size))

    fd = open(r"func_bb.txt", "w")
    fd.write(str(data))
    fd.close()

if __name__ == "__main__":
    main()