#!/usr/bin/env python2

#@author MemoryMeld
#@category 
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import * 
from ghidra.program.model.address import *
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.io import File
from ghidra.app.util.exporter import CppExporter
from re import search

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
import __main__ as ghidra_app


class Analyzer:

    def __init__(self, program=None, timeout=None):

        # Initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)
        self._options = DecompileOptions()
        self._tool = state.getTool()
        self._timeout = timeout
        # Configuration for disassembled code alignment:
        self._address_width = 16  # Width of the address field in characters
        self._byte_sequence_width = 16  # Width of the byte sequence field in characters

        # Format string for displaying disassembled instructions:
        self._instruction_format = ' {{addr:<{0}}} {{byte:<{1}}} {{inst}}\n'.format(
            self._address_width, 
            self._byte_sequence_width
        )


    def set_up_decompiler(self):
        if self._tool is not None:
            options_service = self._tool.getService(OptionsService)
            if options_service is not None:
                tool_options = options_service.getOptions("Decompiler")
                self._options.grabFromToolAndProgram(None, tool_options, program)

        # Eliminate dead code
        self._options.setEliminateUnreachable(True)
        self._decompiler.setOptions(self._options)

        self._decompiler.toggleCCode(True)
        self._decompiler.toggleSyntaxTree(True)
        self._decompiler.setSimplificationStyle("decompile")

        return self._decompiler

    def unoverflow(self, x):
        return (abs(x) ^ 0xff) + 1


    def to_hex(self, integer):
        return '{:02x}'.format(integer)


    def get_function_signature(self, func):
        # Get function signature
        signature = func.getPrototypeString(False, True)
        return signature + '\n'


    def get_instructions(self, func):
        instructions = ''

        # Get instructions in function
        func_addr = func.getEntryPoint()
        insts = ghidra_app.currentProgram.getListing().getInstructions(func_addr, True)

        # Process each instruction
        for inst in insts:
            if ghidra_app.getFunctionContaining(inst.getAddress()) != func:
                break

            instructions += self._instruction_format.format(
                addr=inst.getAddressString(True, True),
                byte=' '.join(
                    [self.to_hex(b) if b >= 0 else self.to_hex(self.unoverflow(b)) for b in inst.getBytes()]),
                inst=inst
            )

        return instructions


    def disassemble_func(self, func):
        return self.get_function_signature(func) + self.get_instructions(func)

    def get_all_functions(self):
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            func = ghidra_app.currentProgram.getFunctionManager().getFunctionAt(address)
            funcs.append(func)
        return funcs
           
    
    def decompile_func(self, func):
        # Decompile
        self._decompiler = self.set_up_decompiler()
        decomp_results = self._decompiler.decompileFunction(func, 0, self._timeout)
        if (decomp_results is not None) and (decomp_results.decompileCompleted()):
            return decomp_results.getDecompiledFunction().getC()
        return ""

    def decompile(self):
            
        pseudo_c = ''

        # Enumerate all functions and decompile each function
        funcs = self.get_all_functions()
        for func in funcs:
            if not func.isThunk():
                dec_func = self.decompile_func(func)
                if dec_func:
                    pseudo_c += dec_func

        return pseudo_c

    def disassemble(self):

        disasm_result = ''

        # Enumerate all functions and disassemble each function
        funcs = self.get_all_functions()
        for func in funcs:
            disasm_result += self.disassemble_func(func)

        return disasm_result

    def list_cross_references(self, dst_func, output_path):
        dst_name = dst_func.getName()
        dst_addr = dst_func.getEntryPoint()
        references = getReferencesTo(dst_addr) # Limited to 4096 records
        xref_addresses = []
        f = open(output_path,'a')
        for xref in references:
            if xref.getReferenceType().isCall(): 
                call_addr = xref.getFromAddress()
                src_func = getFunctionContaining(call_addr)
                if src_func is not None:
                    xref_addresses.append(src_func.getEntryPoint())
                    if ((not src_func.isThunk()) and (xref_addresses.count(src_func.getEntryPoint()) < 2)):
                        results = str(self.decompile_func(src_func))
                        for line in results.splitlines():
                            if search(dst_name, line):
                                print >>f, "Call to {} in {} at {} has function signature of: {}" \
                                    .format(dst_name,src_func.getName(), \
                                        call_addr, line)
        f.close()

    def get_imported_functions(self, output_path):

        import_functions = [ 
            
            # No bounds checking, buffer overflows common
            "strcpy", "sprintf", "vsprintf", "strcat", "getpass",
            "strlen", # needs null terminator

            # Windows specific functions, buffer overflows common
            "makepath", "_makepath", "_splitpath", "snscanf", "_snscanf",

            # Copy functions Windows API and kernel driver functions 
            "RtlCopyMemory", "CopyMemory",

            # When given %s specifier, check for size limit on bytes
            "scanf", "fscanf", "sscanf", "__isoc99_scanf", "__isoc99_fscanf", "__isoc99_sscanf",

            # Often bounds is based on size of input
            "snprintf", "strncpy", "strncat",

            # Printf functions, check for format string 
            "printf", "fprintf",

            # Check for insecure use of environment variables
            "getenv",
            # Check if size arg can contain negative numbers or zero, return value must be checked
            "malloc",
            # Potential implicit overflow due to integer wrapping
            "calloc",
            # Doesn't initialize memory to zero; realloc(0) is equivalent to free
            "realloc",
            # check for incorrect use, double free, use after free
            "free", "_free",

            # I/O functions 
            "fgets", "fread", "fwrite", "read", "recv", "recvfrom", "write",

            # Check for command injection and shell exploitation (runs with shell on machine)
            "system",  "popen",

            # File descriptor handling, might inherit open file descriptors from calling process
            # If sensitive file descriptors are left open or not handled correctly, it can lead to information leak  
            "execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",

            # Common memory copy functions in libc
            "memcpy", "memset", "bcopy"]
         

        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (s.getName() in import_functions) and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            func = ghidra_app.currentProgram.getFunctionManager().getFunctionAt(address)
            funcs.append(func)

        for f in funcs:
           self.list_cross_references(f, output_path)      


def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
    
    f = open(args[0],'w')
    print >>f, 'Xref Results \n-----------------------------\n'
    f.close()

    analyzer = Analyzer()
    analyzer.get_imported_functions(args[0])
    decompiled_source_file = args[1]

    disassembly_file = args[3]

    # Perform selective decompilation process
    pseudo_c = analyzer.decompile()

    # Perform selective dissassembly process
    disassembled = analyzer.disassemble()

    # Save decompilation to output file
    with open(decompiled_source_file, 'w') as fw:
        fw.write(pseudo_c)
        print('[*] saving decompilation to -> {}'.format(decompiled_source_file))

    # Save disassembly to output file
    with open(disassembly_file, 'w') as fw:
        fw.write(disassembled)
        print('[*] saving disassembly to -> {}'.format(disassembly_file))
    
    exporter = CppExporter()
    options = [Option(CppExporter.CREATE_HEADER_FILE, False)]
    exporter.setOptions(options)
    exporter.setExporterServiceProvider(analyzer._tool)
    f = File(args[2])
    exporter.export(f, ghidra_app.currentProgram, None, TaskMonitor.DUMMY)


if __name__ == '__main__':
    run()
