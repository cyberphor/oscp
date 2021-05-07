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
Set the current working directory to be where the program (i.e. %p) being debugged is located. 
```bash
!mona config -set workingfolder c:\mona\%p
```

Toggle between command history.
```bash
# ESC + <arrow>
```

#### Controlling the EIP Register
Find all instances of a Metasploit Pattern (hence "msp"). The example below will search 2400 bytes from the ESP register (the default is to search the entire Stack Frame). The alternative to this is manually looking at the EIP register in the Registers pane (in the CPU window). Pay attention the offset value (this represents where EIP is in the BOF you sent; if you know this value, you know exactly where in your BOF you need to place the Return Address that will point to your shellcode). For example, if the example output below means you must place your desired Return Address 1978 bytes into your BOF in order for it to accuratey land in the EIP register. 
```bash
!mona findmsp -distance 2400

# example output
[+] Examining registers
    EIP contains normal pattern : 0x6f43396e (offset 1978)
```

### Generate a Byte Array of Bad Characters
This step is important for knowing what characters will prevent our shellcode from working. 
```bash
!mona bytearray -b "\x00"
```

```python
payload = ''
for x in range(1, 256):
  payload += "\\x" + "{:02x}".format(x)
```

Always re-copy the address. It will change as you remove bad characters from your BOF. 
```bash
!mona compare -f C:\mona\bytearray.bin -a <address>
```

### Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"
```


## References
* https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/
