#!/usr/bin/env python3

try:
    import ghidra
    in_ghidra = True
except:
    from ghidra_bridge import *
    in_ghidra = False

import sys

# Offset into the buffer pointed to by rtos_data in the tasklist datatype
# This is the real entrypoint of the task, which is being called by the RTOS wrapper
# Seems to be constant between versions
RTOS_buffer_entrypoint = 0x30

def main(tasklist):
    # Layout might be different for other verisons, you probably need to adapt this
    # Or create a `tasklist` datatype in ghidra yourself before running this script
    # A tasklist needs at least these field names for this script to work properly:
    #     * `next`: points to the next tasklist
    #     * `entrypoint`: entrypoint into the task, this one is ignored for RTOS wrappers, because the real entry point is stored in the rtos_data here
    #     * `name`: defines the name of the task
    #     * `stackframe_begin`, `stackframe_end`: Points to the stackframe
    #     * `rtos_data`: Points to additional data for tasks wrapped in RTOS glue code. The real entry point for the task is normally at rtosdata + 0x30
    bi_dtm = ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager()
    dtm = currentProgram.getDataTypeManager()
    
    tasklist_t = ghidra.program.model.data.StructureDataType("tasklist", 0)
    tasklist_ptr = bi_dtm.getPointer(tasklist_t)
    void_ptr = bi_dtm.getPointer(bi_dtm.getDataType("/void"))
    byte_ptr = bi_dtm.getPointer(bi_dtm.getDataType("/byte"))
    int_t = bi_dtm.getDataType("/int")
    char_t = bi_dtm.getDataType("/char")
    
    tasklist_t.add(tasklist_ptr, 4, "next", "")
    tasklist_t.add(tasklist_ptr, 4, "prev", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(char_t, 4, "magic", "")
    tasklist_t.add(char_t, 8, "name", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(void_ptr, 4, "entrypoint", "")
    tasklist_t.add(void_ptr, 4, "stackframe_begin", "")
    tasklist_t.add(void_ptr, 4, "stackframe_end", "")
    tasklist_t.add(void_ptr, 4, "stackframe_ptr", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(void_ptr, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(int_t, 4, "", "")
    tasklist_t.add(char_t, 8, "", "")
    tasklist_t.add(byte_ptr, 4, "rtos_data", "")
    tasklist_t.add(void_ptr, 4, "", "")
    tasklist_t.add(void_ptr, 4, "", "")
    
    start()
    dtm.addDataType(tasklist_t, ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER)
    tasklist_t = getDataTypes("tasklist")
    if len(tasklist_t) > 1:
        print("Too many `tasklist` data types. Please delete the duplicates before running this script")
        return 0
    tasklist_t = tasklist_t[0]
    offsets = {}
    length = {}
    for datatype in tasklist_t.getComponents():
        name = datatype.getFieldName()
        if name:
            offsets[name] = datatype.getOffset()
            length[name] = datatype.getLength()
    curr = tasklist
    amount = 0
    while True:
        name_bytes = getBytes(toAddr(curr + offsets["name"]), length["name"])
        name_end = name_bytes.index(0) if 0 in name_bytes else -1
        if name_end != -1:
            name_bytes = [ name_bytes[i] for i in range(name_end) ]
        name = ''.join(list(map(chr, name_bytes)))
        clearListing(ghidra.program.model.address.AddressSet(toAddr(curr), toAddr(curr).add(tasklist_t.getLength())))
        createData(toAddr(curr), tasklist_t)
        createLabel(toAddr(curr), "tasklist_{}".format(name), True)
        stackframe_begin = getInt(toAddr(curr + offsets["stackframe_begin"]))
        stackframe_end = getInt(toAddr(curr + offsets["stackframe_end"]))
        createLabel(toAddr(stackframe_begin), "task_{}_stackframe_begin".format(name), True)
        createLabel(toAddr(stackframe_end), "task_{}_stackframe_end".format(name), True)
        rtos_buffer = getInt(toAddr(curr + offsets["rtos_data"]))
        entry_point = getInt(toAddr(curr + offsets["entrypoint"]))
        if rtos_buffer:
            entry_point = getInt(toAddr(rtos_buffer + RTOS_buffer_entrypoint))
        print("Tasklist: {}".format(hex(curr)))
        print("Name: {}".format(name))
        print("Entry point: {}".format(hex(entry_point)))
        print("Stackframe: {} - {}".format(hex(stackframe_begin), hex(stackframe_end)))
        if entry_point % 2 == 0:
            print("Normal")
        else:
            print("Thunk")
        disassemble(toAddr(entry_point))
        # Thunk function seem to be address + 1, so to get the real address, we have to remove the + 1 or Ghidra won't create the function
        createFunction(toAddr(entry_point - entry_point % 2), "task_{}".format(task))
        curr = getInt(toAddr(curr + offsets["next"]))
        amount += 1
        # We've come full circle!
        if curr == tasklist:
            break
    print("Loaded {} tasks".format(amount))
    end(True)

if __name__ == "__main__":
    arg = None
    if len(sys.argv) != 2:
        if in_ghidra:
            arg = askAddress("Where is the tasklist?", "Tasklist location:").getValue()
        else:
            print("Usage: identify_tasks <tasklist Addr>")
            sys.exit(1)
    else:
        arg = int(sys.argv[1], 16)

    try:
        ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=10)
        main(arg)
    except ConnectionRefusedError:
        print("Ghidra bridge needs to be running")
    except Exception as e:
        print(e)
        end(False)
