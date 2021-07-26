# Algernon
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [FTP](#ftp)
    * [HTTP](#http)
    * [RPC](#rpc)
    * [NetBIOS](#netbios)
    * [SMB](#smb)
  * [OS](#os)
    * [Nmap OS Discovery Scan](#nmap-os-discovery-scan)
    * [Nmap OS Discovery Scan via SMB](#nmap-os-discovery-scan-via-smb)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing) 
    * [Default Credentials](#default-credentials)
  * [CVE-2019-7214](#cve-2019-7214)
    * [EDB-ID-49216](#edb-id-49216)
  * [EDB-ID-48580](#edb-id-48580)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)

# Summary
* Hostname: algernon
* Description: Algernon sure is a clever one.
* IP address: 192.168.132.65
* MAC address: (ref:)
* Domain: WORKGROUP
* TCP Ports and Services
  * 21
    * Microsoft ftpd
  * 80
    * Microsoft IIS httpd 10.0
  * 445
    * SMB
  * 9998
    * Microsoft IIS httpd 10.0
    * SmarterMail Free Version - 100.0.6919 (ref: /about/checkup)
  * 17001
    * MS .NET Remoting services
    * SmarterMail
* OS
  * Distro: Windows 10 (ref: Nmap)
  * Kernel: 10.0.18363 N/A Build 18363 (ref: systeminfo via post-exploitation)
  * Architecture: x64 (ref: systeminfo post-exploitation)
* Users 
  * administrator  (ref: confirmed using net user via post-exploitation)
  * admin (ref: logs found during an anonymous FTP session)
* Vulnerabilities and Exploits
  * CVE-2019-7214 (ref: manual research of TCP port 17001)
    * EDB-ID-56789 (ref: same as above)
  * EDB-ID-48580 (ref: searchsploit)
* Tools Used
  * Nmap
* Flag
  * 9bfc6960c73baef64da04ecbec4d0a8f
* Hints
  * n/a

# Enumerate
## Setup
```bash
TARGET=192.168.132.65
NAME=algernon
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-29 23:53 EDT
Nmap scan report for 192.168.132.65
Host is up (0.14s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
9998/tcp  open  distinct32
17001/tcp open  remoting      MS .NET Remoting services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.14 seconds
```

## Services
### FTP
```bash
cd loot
touch README.too
ftp $TARGET 21
put README.too
ls
binary
prompt
mget *
exit
cat * 

# output
03:35:45.726 [192.168.118.6] User @ calling create primary system admin, username: admin
03:35:47.054 [192.168.118.6] Webmail Attempting to login user: admin
03:35:47.054 [192.168.118.6] Webmail Login successful: With user admin
03:35:55.820 [192.168.118.6] Webmail Attempting to login user: admin
03:35:55.820 [192.168.118.6] Webmail Login successful: With user admin
03:36:00.195 [192.168.118.6] User admin@ calling set setup wizard settings
03:36:08.242 [192.168.118.6] User admin@ logging out
```

###  HTTP
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb-common

# output
---- Scanning URL: http://192.168.132.65/ ----
==> DIRECTORY: http://192.168.132.65/aspnet_client/ 
```
```bash
dirb http://$TARGET:9998 -r -z10 -o scans/$NAME-dirb-common

# output
---- Scanning URL: http://192.168.132.65:9998/ ----
+ http://192.168.132.65:9998/api (CODE:302|SIZE:156)                                                                                  
+ http://192.168.132.65:9998/aux (CODE:302|SIZE:162)                                                                                  
+ http://192.168.132.65:9998/com1 (CODE:302|SIZE:163)                                                                                 
+ http://192.168.132.65:9998/com2 (CODE:302|SIZE:163)                                                                                 
+ http://192.168.132.65:9998/com3 (CODE:302|SIZE:163)                                                                                 
+ http://192.168.132.65:9998/con (CODE:302|SIZE:162)                                                                                  
+ http://192.168.132.65:9998/download (CODE:500|SIZE:36)                                                                              
+ http://192.168.132.65:9998/Download (CODE:500|SIZE:36)                                                                              
+ http://192.168.132.65:9998/favicon.ico (CODE:200|SIZE:32038)                                                                        
==> DIRECTORY: http://192.168.132.65:9998/fonts/                                                                                      
==> DIRECTORY: http://192.168.132.65:9998/interface/                                                                                  
+ http://192.168.132.65:9998/lpt1 (CODE:302|SIZE:163)                                                                                 
+ http://192.168.132.65:9998/lpt2 (CODE:302|SIZE:163)                                                                                 
+ http://192.168.132.65:9998/nul (CODE:302|SIZE:162)                                                                                  
+ http://192.168.132.65:9998/prn (CODE:302|SIZE:162)                                                                                  
==> DIRECTORY: http://192.168.132.65:9998/reports/                                                                                    
==> DIRECTORY: http://192.168.132.65:9998/scripts/                                                                                    
==> DIRECTORY: http://192.168.132.65:9998/Scripts/                                                                                    
==> DIRECTORY: http://192.168.132.65:9998/services/                                                                                   
==> DIRECTORY: http://192.168.132.65:9998/Services/                                                                                   
+ http://192.168.132.65:9998/views (CODE:200|SIZE:0)
```
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.132.65
+ Target Hostname:    192.168.132.65
+ Target Port:        9998
+ Start Time:         2021-06-30 17:07:24 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: /interface/root
+ Uncommon header 'request-id' found, with contents: fda78b2b-5d4c-4689-87d8-eb07df0f5d9d
+ 1601 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2021-06-30 17:10:03 (GMT-4) (159 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
The target is not vulnerable to Shell Shock via HTTP.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock

# output
NSTR.
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
Doing NBT name scan for addresses from 192.168.132.65

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
session setup failed: NT_STATUS_ACCESS_DENIED
```
```bash
smbmap -H $TARGET

# output
[!] Authentication error on 192.168.132.65
```

The target is not vulnerable to EternalBlue.
```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010

# output
NSTR
```

The target is not vulnerable to SambaCry.
```bash
# check if vulnerable to SambaCry
sudo nmap $TARGET -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-smb-vuln-cve-2017-7494

# output
NSTR
```

### TCP Port 9998
This port exposed the admin console to SmarterMail.
```bash
telnet 192.168.132.65 9998
Trying 192.168.132.65...
Connected to 192.168.132.65.
Escape character is '^]'.
helo

# output
HTTP/1.1 400 Bad Request
Content-Type: text/html; charset=us-ascii
Server: Microsoft-HTTPAPI/2.0
Date: Wed, 30 Jun 2021 04:30:20 GMT
Connection: close
Content-Length: 326

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Bad Request</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Bad Request - Invalid Verb</h2>
<hr><p>HTTP Error 400. The request verb is invalid.</p>
</BODY></HTML>
Connection closed by foreign host.
```

### TCP Port 17001
This port exposes .NET remoting endpoint (???).
```bash
telnet 192.168.132.65 17001
Trying 192.168.132.65...
Connected to 192.168.132.65.
Escape character is '^]'.
helo

# output
.NETSystem.Runtime.Remoting.RemotingException: Tcp channel protocol violation: expecting preamble.
   at System.Runtime.Remoting.Channels.Tcp.TcpSocketHandler.ReadAndMatchPreamble()
   at System.Runtime.Remoting.Channels.Tcp.TcpSocketHandler.ReadVersionAndOperation(UInt16& operation)
   at System.Runtime.Remoting.Channels.Tcp.TcpServerSocketHandler.ReadHeaders()
   at System.Runtime.Remoting.Channels.Tcp.TcpServerTransportSink.ServiceRequest(Object state)
   at System.Runtime.Remoting.Channels.SocketHandler.ProcessRequestNow()Connection closed by foreign host.
```

## OS
### Nmap OS Discovery Scan
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
```

### Nmap OS Discovery Scan via SMB
```bash
sudo nmap $TARGET -p445 --script smb-os-discovery -oN scans/$NAME-nmap-os-smb

# output
NSTR
```

# Exploit 
## Password Guessing
### Default Credentials
This did not work (the target requires a domain name for the username/email address).
```bash
# SmarterMail
# admin:admin

# output
That domain was not found. Double check your email address.
```

## CVE-2019-7214
Online research of TCP port 17001 lead to information about CVE-2019-7214 (RCE vulnerability) and EDB-ID-49216 (exploit POC). 

Vulnerability description: SmarterTools SmarterMail 16.x before build 6985 allows deserialization of untrusted data. An unauthenticated attacker could run commands on the server when port 17001 was remotely accessible. This port is not accessible remotely by default after applying the Build 6985 patch.

### EDB-ID-49216
This did not work until I used TCP port 17001 as both my target and remote port.
```bash
searchsploit SmarterMail
mkdir edb-id-49216
cd edb-id-49216
searchsploit -x 49216
vim 49216.py # edit variables: 
pyenv global 3.9.5 
sudo nc -nvlp 17001
python 49216.py
```

## EDB-ID-48580
I did not try this exploit as it requires valid credentials.
```bash
searchsploit SmarterMail
mkdir edb-id-48580
cd edb-id-48580
searchsploit -x 48580
vim 48580 # realized must supply valid username/password
```

# Explore
NSTR

# Escalate
NSTR

# Lessons Learned
* TCP port 17001 - SmarterTools SmarterMail 16.x before build 6985 allows deserialization of untrusted data. An unauthenticated attacker could run commands on the server when port 17001 was remotely accessible. This port is not accessible remotely by default after applying the Build 6985 patch. References: [CVE-2019-7214] (https://www.speedguide.net/port.php?port=17001).
* Not having the email domain for the target prevented me from using Hydra to brute force the admin console. 
* When your reverse shell fails, try using the targeted port as the port the victim calls back (target = 17001, rport = 17001).
* Thoroughly research where the admin console is for a web app. Finding "/about/checkup" online allowed me to confirm the build version (6919; everything 6985 and below is vulnerable) and vulnerability (CVE-2019-7214).
* Use `nmap -A` to scan a port you want more info about.
* Use `curl -L http:\\10.11.12.13` to confirm information about a port. Doing this for Algernon would have revealed the vulnerable build version (6919) in the HTTP header reply.
