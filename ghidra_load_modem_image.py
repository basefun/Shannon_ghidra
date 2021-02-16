#!/usr/bin/env python3

from ghidra_bridge import *
from pwn import *

import sys

context.arch='arm'
context.endian='little'

def read_entry(f):
    # Source: https://i.blackhat.com/USA-20/Wednesday/us-20-Hernandez-Emulating-Samsungs-Baseband-For-Security-Testing.pdf
    # Slide 21
    return f.read(12).rstrip(b'\x00').decode("ASCII"), u32(f.read(4)), u32(f.read(4)), u32(f.read(4)), u32(f.read(4)), u32(f.read(4))

def main(path):
    with open(path, 'rb') as f:
        print("Removing existing ghidra memory map...")
        # Start a transaction. Rollback on error
        start()
        memory = currentProgram.getMemory()
        for block in memory.getBlocks():
            memory.removeBlock(block, monitor)
            print("done")
            print()

        name, toc_offset, load_address, toc_size, crc, entry_id = read_entry(f)
        assert entry_id == 1, "First entry is not the TOC"
        
        print("Adding new memory maps...")
        print("Name:", name)
        print("Offset:", hex(toc_offset))
        print("Load Address:", hex(load_address))
        print("Size:", hex(toc_size))
        print("CRC:", hex(crc))
        print("Count/Entry ID:", hex(entry_id))
        print()
        
        while f.tell() < toc_offset + toc_size:
            name, offset, load_address, size, crc, entry_id = read_entry(f)
            if size == 0:
                print("Empty entry detected. Skipping...")
                print()
                continue
            
            print("Name:", name)
            print("Offset:", hex(offset))
            print("Load Address:", hex(load_address))
            print("Size:", hex(size))
            print("CRC:", hex(crc))
            print("Count/Entry ID:", hex(entry_id))
            print()
            memory.createInitializedBlock(name, toAddr(load_address), memory.getAllFileBytes()[0], offset, size, True)
    print("done")
    print()

    print("completed - comitting changes")
    end(True)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ghidra_load_modem_image <file>")

    try:
        ghidra_bridge.GhidraBridge(namespace=globals())
        main(sys.argv[1])
    except ConnectionRefusedError:
        print("Ghidra bridge needs to be running")
