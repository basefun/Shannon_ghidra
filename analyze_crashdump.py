#!/usr/bin/env python3

from ghidra_bridge import *

import sys
import inspect
import readline

CRASHDATA_ADDR = 0xe0ebfc
CRASHLOCATION_OFFSET = 0x34
CRASH_STACKFRAME_OFFSET = 0x48

# Offsets in the crashdata structure of the saved registers
REGISTER_OFFSETS = {
    "r0": 0x00,
    "r1": 0x04,
    "r2": 0x08,
    "r3": 0x0c,
    "r4": 0x10,
    "r5": 0x14,
    "r6": 0x18,
    "r7": 0x1c,
    "r8": 0x20,
    "r9": 0x24,
    "r10": 0x28,
    "r11": 0x2c,
    "r12": 0x30
}

current_stackframe = 0

class Completer:
    def complete(self, text, state):
        buff = readline.get_line_buffer()
        line = buff.split()
        values = []
        index = len(line) - 1 + (1 if not buff or buff.endswith(' ') else 0)
        if index == 0:
            values = list(commands.keys())
        elif line[0] in commands:
            values = commands[line[0]][1][index - 1]
            if hasattr(values, '__call__'):
                values = values()
        return [x + ' ' for x in values if x.startswith(text)][state]

def display(elem):
    if elem == None:
        return None

    if isinstance(elem, int):
        return hex(elem)
    elif isinstance(elem, list):
        return "[" + ', '.join([ display(x) for x in elem ]) + "]"
    else:
        return str(elem)

def readElement(dtype, length, addr, register, count = 1):
    if register != 'None':
        return bridge.remote_eval("dtype.getValue(ghidra.program.model.mem.MemoryBufferImpl(currentProgram.getMemory(), toAddr(location), length), ghidra.docking.settings.SettingsImpl(), length).getValue()", dtype = dtype, length = length, location = CRASHDATA_ADDR + REGISTER_OFFSETS[register])

    if isinstance(dtype, ghidra.program.model.data.Array):
        elements = readElement(dtype.getDataType(), length, addr, register, count * dtype.getNumElements())
        if count != 1:
            return [elements[i:i+count] for i in range(0, len(elements), count)]
        else:
            return elements

    elements = bridge.remote_eval("[dtype.getValue(ghidra.program.model.mem.MemoryBufferImpl(currentProgram.getMemory(), toAddr(addr + dtype.getLength() * i), length), ghidra.docking.settings.SettingsImpl(), length).getValue() for i in range(count)]", dtype = dtype, addr = addr, length = length, count = count)
    
    if count == 1:
        return elements[0]
    else:
        return elements

def printStackFrame(stackframes, frame = None):
    if frame == None:
        frame = current_stackframe
    frame = int(frame)
    if frame < 0 or frame >= len(stackframes):
        print("Invalid stackframe")
        return
    pc = stackframes[frame][0]
    sp = stackframes[frame][1]
    saved_registers = stackframes[frame][2]
    func = getFunctionContaining(toAddr(pc))
    if not func:
        print(f"Frame #{frame} in unknown function")
        return
    print(f"Frame #{frame} in function `{func.getName()}`")
    result = bridge.remote_eval("[(var.getName(), var.getDataType(), var.getLength(), var.getStackOffset() if var.hasStackStorage() else None, str(var.getRegister())) for var in func.getLocalVariables()]", func = func)
    if result:
        for (var_name, dtype, length, stack_offset, reg) in result:
            # Register values are only valid for the crash location, don't read their values in other stackframes
            representation = readElement(dtype, length, sp + stack_offset if stack_offset else None, reg) if stack_offset or (reg != 'None' and frame == 0) else "<value unknown>"
            print(f"  {var_name}: {dtype.getName()} ({(reg != 'None' and reg) or ('sp' + hex(stack_offset) if stack_offset else 'N/A')}) = {display(representation) or 'N/A'}")
    else:
        print("No local variables")
    if saved_registers:
        print("Saved registers:")
        values = bridge.remote_eval("[getInt(toAddr(sp - i * 4 - 4)) for i in range(count)][::-1]", sp = sp, count = len(saved_registers))
        for reg, val in zip(saved_registers, values):
            print("  ", reg, "=", hex(val))

def backtrace(stackframes):
    names = bridge.remote_eval("[getFunctionContaining(toAddr(stackframes[i][0])).getName() if getFunctionContaining(toAddr(stackframes[i][0])) else None for i in range(len(stackframes))]", stackframes = stackframes)
    for i in range(len(stackframes)):
        print(f"{ '->' if i == current_stackframe else '  ' } #{i} at {hex(stackframes[i][0])} in `{names[i] or 'unknown function'}`")

def select(stackframes, target):
    if int(target) >= 0 and int(target) < len(stackframes):
        global current_stackframe
        current_stackframe = int(target)
    else:
        print("Invalid stackframe")

def printValue(stackframes, name):
    if name == "registers":
        values = bridge.remote_eval("[getInt(toAddr(base + offset)) for offset in registers]", base = CRASHDATA_ADDR, registers = REGISTER_OFFSETS.values())
        for reg, value in zip(REGISTER_OFFSETS, values):
            print(f"  {reg}: {hex(value)}")
        return
    
    value = None
    if name in REGISTER_OFFSETS:
        value = getInt(toAddr(CRASHDATA_ADDR + REGISTER_OFFSETS[name]))
    else:
        print("Invalid identifier")

    if value:
        print(name, "=", hex(value))
    else:
        print("Invalid variable")

def showHelp(stackframes):
    for name in commands:
        spec = inspect.getfullargspec(commands[name][0])
        names = spec.args[1:]
        provided = spec.defaults or []
        print(name, ' '.join(names[:len(names) - len(provided)]) + ("[" + ' '.join(names[-len(provided):]) + "]" if provided else ""))

def gotoSymbol(stackframes, symbol):
    if symbol == "crashlocation":
        setCurrentLocation(toAddr(getInt(toAddr(CRASHDATA_ADDR + CRASHLOCATION_OFFSET))))
        return
    if symbol == "stack":
        setCurrentLocation(toAddr(getInt(toAddr(CRASHDATA_ADDR + CRASH_STACKFRAME_OFFSET))))
        return
    if symbol == "stackframe":
        setCurrentLocation(toAddr(stackframes[current_stackframe][0]))
        return
    try:
        frame = int(symbol)
        if frame < 0 or frame >= len(stackframes):
            print("Invalid stackframe")
            return
        setCurrentLocation(toAddr(stackframes[frame][0]))
        return
    except NumberFormatException:
        pass
    print("Invalid location")

def discoverStackFrames(stackframes):
    pc = getInt(toAddr(CRASHDATA_ADDR + CRASHLOCATION_OFFSET))
    sp = getInt(toAddr(CRASHDATA_ADDR + CRASH_STACKFRAME_OFFSET))
    print(f"Crash location: {hex(pc)}, stack: {hex(sp)}")
    stackframes.clear()
    while func := getFunctionContaining(toAddr(pc)):
        assert getFirstInstruction(func).getMnemonicString() == "push", f"Function {func.getName()} is suspicious, doesn't start with a push instruction"
        # Ghidra's stackframe is empty if there are no local variables
        # So we have to determine the space occupied by saved registers ourselves if that's the case
        framesize = bridge.remote_eval("func.getStackFrame().getFrameSize() or len(getFirstInstruction(func).getOpObjects(0)) * 4", func = func)
        # Align stack to 8 bytes according to Arm EABI
        sp += (framesize + 7) // 8 * 8
        stackframes.append((pc, sp, bridge.remote_eval("[str(reg) for reg in getFirstInstruction(func).getOpObjects(0)]", func = func)))
        if pc == 0x0:
            break
        pc = bridge.remote_eval("getInt(toAddr(sp - 4 + func.getStackFrame().getReturnAddressOffset()))", func = func, sp = sp)
    print(f"Stackframe discovery ended at sp `{hex(sp)}` and pc `{hex(pc)}`", "(good)" if pc == 0 else "(bad, maybe the stack is corrupted or Ghidra does not know that function)")
    if pc != 0x0:
        stackframes.append((pc, sp, None))
        
commands = {
    "analyze": (discoverStackFrames, []),
    "showframe": (printStackFrame, [[]]),
    "backtrace": (backtrace, []),
    "select": (select, [[]]),
    "print": (printValue, [["registers", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"]]),
    "help": (showHelp, []),
    "goto": (gotoSymbol, [["crashlocation", "stack", "stackframe"]])
}

def main():
    stackframes = []
    discoverStackFrames(stackframes)
    
    print(f"Found {len(stackframes)} stackframes")

    printStackFrame(stackframes, 0)

    try:
        while (s := input("> ")) != 'q':
            sp = s.split()
            if sp[0] in commands:
                func = commands[sp[0]][0]
                spec = inspect.getfullargspec(func)
                names = spec.args[1:]
                provided = spec.defaults or []
                if len(sp) - 1 < len(names) - len(provided):
                    print("Missing arguments:", ', '.join(names[len(sp) - 1:len(names) - len(provided)]))
                elif len(sp) - 1 > len(names):
                    print("Too many arguments")
                else:
                    func(stackframes, *sp[1:])
            else:
                print("Invalid command")
    except EOFError:
        print()

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: analyze_crashdump")

    try:
        global bridge
        bridge = ghidra_bridge.GhidraBridge(namespace=globals())
        readline.set_completer(Completer().complete)
        readline.parse_and_bind('tab: complete')
        main()
    except ConnectionRefusedError:
        print("Ghidra bridge needs to be running")
