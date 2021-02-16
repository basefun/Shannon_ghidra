#!/usr/bin/env python3

import sys

try:
    import ghidra
except:
    from ghidra_bridge import *
    try:
        ghidra_bridge.GhidraBridge(namespace=globals())
    except ConnectionRefusedError:
        print("Ghidra bridge needs to be running")
        sys.exit(1)

# Samsung S6 Edge
# segments = [[0x40000000, 0x8000000, "MAIN"], [0x4000000, 0x10000, None], [0x4800000, 0x4000, None], [0xe0000000, 0x57000, None], [0x2f00, 0x100, None]]

# Samsung S5 Mini
segments = [[0x10000, 0x6000000, "MAIN"], [0x20000000, 0x10000, None], [0x20800000, 0x8000, None], [0xe0200000, 0x40000, None]]

def main():
    memory = currentProgram.getMemory()
    print("Removing existing ghidra memory map...")
    # Start a transaction. Rollback on error
    start()
    for block in memory.getBlocks():
        memory.removeBlock(block, monitor)
        print("done")
        print()

    offset = 0x0
    for segment in segments:
        memory.createInitializedBlock(segment[2] or hex(segment[0]), toAddr(segment[0]), memory.getAllFileBytes()[0], offset, segment[1], False)
        offset += segment[1]

    print("completed - comitting changes")
    end(True)

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: ghidra_load_ramdump")
        sys.exit(1)

    main()
