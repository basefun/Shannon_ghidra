#!/usr/bin/env python3

import sys
try:
    import ghidra
    @classmethod
    def glue_eval(self, expression, **kwargs):
        return eval(expression)
    
    bridge = type('', (), dict(remote_eval=glue_eval))
except:
    from ghidra_bridge import *
    try:
        bridge = ghidra_bridge.GhidraBridge(namespace=globals())
    except ConnectionRefusedError:
        print("Ghidra bridge needs to be running")
        sys.exit(1)

def check_tasklist(addr):
    """
    Check if the given address could be the starting point of a tasklist. Basically checks if addr->next->prev == addr
    """
    # tasklist->next->prev == tasklist
    if getInt(toAddr(getInt(addr)).add(4)) == addr.getOffset():
        return ""
    return "(Warning: layout seems to differ from the S5 mini, the location is probably off by some bytes, you will need to create your own tasklist struct with the correct layout if you want to run `./identify_tasks.py`)"

def main():
    TASKLIST_OFFSET = 0xc
    addr = bridge.remote_eval("findBytes(toAddr(0x0), b\"KSATmainTask\", 2)", timeout_override = 20)

    if not addr:
        print("No tasklist found")
    elif len(addr) == 1:
        print("Found tasklist at: %s %s" % (hex(addr[0].getOffset() - TASKLIST_OFFSET), check_tasklist(toAddr(addr[0].getOffset() - TASKLIST_OFFSET))))
    else:
        print("Multiple possible tasklists found:")
        for a in addr:
            print("\t %s %s" % (hex(a.getOffset() - TASKLIST_OFFSET), check_tasklist(toAddr(a.getOffset() - TASKLIST_OFFSET))))

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: find_tasklist")

    main()
