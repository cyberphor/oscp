# Cheatsheet - Buffer Overflows (BOF)
## Immunity Debugger
```bash
File > Open # open a program for debugging; provide file name & arguments
Debug > Step into # follow the execution flow of a function
Debug > Step over # execute a function and return from it
```

How to find and proceed to the Main function of a program.
```bash
- [Right-click Assembly pane] > Search for > All referenced text strings
- Double-click on the correct result (and return to the Assembly pane)
- Highlight the text of interest (ex: strcpy) & press F2 (set a breakpoint)
- Debug > Run (execution will stop just before your breakpoint)
- Debug > Step into # watch program execution "frame by frame"
```

How to reset the view to the original layout (instruction, registers, memory, and stack panes). 
```bash
# option 1
View > CPU # then, maximize the CPU window

# option 2
ALT + c # then, maximize the CPU window
```

### Mona.py
Configure a working folder (ex: set the default location to a folder that contains your Python scripts). 
```bash
!mona config -set workingfolder c:\mona\%p
```

#### Controlling the EIP Register
Find all instances of a Metasploit Pattern (hence "msp"). The example below will search 2400 bytes from the ESP register (the default is to search the entire Stack Frame). The alternative to this is manually looking at the EIP register in the Registers pane (in the CPU window). 
```bash
!mona findmsp -distance 2400

# example output
[+] Examining registers
    EIP contains normal pattern : 0x6f43396e (offset 1978)
```

## References
* https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/
