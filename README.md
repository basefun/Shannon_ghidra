Contains various ghidra scripts to aid in reversing the modem boot code. Some scripts (`analyze_crashdump` and `ghidra_load_modem_image`) require [Ghidra Bridge](https://github.com/justfoxing/ghidra_bridge). The latter also requires [pwntools](https://github.com/Gallopsled/pwntools).

These scripts are targeting the SM-G800F mobile phone. These will likely work on other Samsung devices as well, but may need adjustments, because memory locations/struct layouts may have changed.

Script list:
* `find_tasklist.py`: Attempts to find the linked list, which holds all the tasks of the RTOS. This script is looking for a `mainTask`, which seems to be present. The reported address will be off by a few bytes if the struct layout has changed.
* `identify_tasks.py`: Labels all tasks from the linked list and assigns an automatically created `tasklist` datatype to their in memory locations. If you have another version of the firmware, you will most likely need to create a `tasklist` datatype with the correct layout beforehand.
* `ghidra_load_modem_image.py`: Reads the memory map from the `modem.bin` file from Samsung firmware images. You first need to import the `modem.bin` file into ghidra and run this script afterwards.
* `ghidra_load_ramdump.py`: Loads the memory map from a crashdump of the Cellular Processor. For other models, the memory layout may be different. If that's the case, you need to reverse the boot code of the modem firmware image (see `ghidra_load_modem_image`) and look for the `DUMP` code branch.
* `analyze_crashdump.py`: GDB like interface to display backtraces, local variables, etc. You should first run ghidra's auto analysis on the binary, so that this script can find the functions in the backtrace and work out the stackframes for each function.
