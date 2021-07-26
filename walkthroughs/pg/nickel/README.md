# Nickel
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
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: nickel 
* Description: 
* IP Address: 192.168.222.99
* MAC Address: (ref:) 
* Domain: nickel
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Mon Jul 26 14:37:47 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/nickel-nmap-complete 192.168.222.99
Nmap scan report for 192.168.222.99
Host is up (0.076s latency).
Not shown: 65535 open|filtered ports, 65528 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
3389/tcp  open  ms-wbt-server
8089/tcp  open  unknown
33333/tcp open  dgi-serv

# Nmap done at Mon Jul 26 14:41:58 2021 -- 1 IP address (1 host up) scanned in 250.77 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Mon Jul 26 14:43:05 2021 as: nmap -sV -sC -pT:21,22,135,139,3389,8089,33333 -oN scans/nickel-nmap-versions 192.168.222.99
Nmap scan report for 192.168.222.99
Host is up (0.20s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2021-07-26T18:43:23+00:00
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2021-07-25T18:34:13
|_Not valid after:  2022-01-24T18:34:13
|_ssl-date: 2021-07-26T18:44:43+00:00; -1s from scanner time.
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 26 14:44:44 2021 -- 1 IP address (1 host up) scanned in 99.37 seconds
```

### Operating System
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-26 14:49 EDT
Nmap scan report for 192.168.222.99
Host is up (0.074s latency).
Not shown: 994 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
3389/tcp open  ms-wbt-server
8089/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|XP (85%)
OS CPE: cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (85%), Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.45 seconds
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

### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://10.11.12.13
```

### HTTP
The target is NOT vulnerable to Shellshock.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-scripts-http-shellshock-80
# replace the lines above with the actual scan results
```

Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://$TARGET:80 /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80
# replace the lines above with the actual scan results
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
```
```
srvinfo

# output
NSTR
```
```
netshareenum

# output
NSTR
```

### NetBIOS
```bash
nbtscan $TARGET

# output
NSTR
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
NSTR
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET

# output
NSTR
```

Victor was able to download files from the accessible SMB share(s).
```bash
cd loot
smbclient \\\\$TARGET\\$SHARE
prompt
mget *

# output
NSTR
```

The target is NOT vulnerable to EternalBlue.
```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010
# replace the lines above with the actual scan results
```

The target is NOT vulnerable to SambaCry.
```bash
# check if vulnerable to SambaCry
sudo nmap $TARGET -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-scripts-smb-vuln-cve-2017-7494
# replace the lines above with the actual scan results
```

### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-scripts-rdp-ntlm-info
# replace the lines above with the actual scan results
```

```bash
rdesktop $TARGET

# output
Autoselecting keyboard map 'en-us' from locale
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Failed to connect, CredSSP required by server (check if server has disabled old TLS versions, if yes use -V option).
```

### Postgres
```bash
psql -U postgres -p 5437 -h $TARGET # postgres:postgres
SELECT pg_ls_dir('/');
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Default Credentials
```bash
# CMS Web App 9000
# admin:admin
```

#### Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"

# output
NSTR
```

#### Patator
```bash
patator http_fuzz url=http://$TARGET/$LOGIN method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyout.txt -x ignore:fgrep=Unauthorized
```

### CVE-2021-1234
#### EDB-ID-56789
```bash
searchsploit foo
mkdir edb-id-56789
cd edb-id-56789
searchsploit -x 56789
```

#### cyberphor POC
```bash
git clone https://github.com/cyberphor/cve-2021-1234-poc.git
cd cve-2021-56789-poc
```

#### Metasploit Module
```bash
msfconsole
search ???
use exploit/???/???
set LHOST tun0
set RHOST $TARGET
run
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
#### Linux
```bash
whoami
cat /etc/passwd
find / -perm -u=s -type f 2> /dev/null
cat /etc/crontab
```

#### Windows
```bash
whoami /priv
systeminfo
net user
dir c:\
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* Nmap
* Patator
* Intruder from Burp Suite

## Hints
* Scan all ports
* Identify every application and their version
* Try harder

## Flags
* local.txt = abcdef0123456789
* proof.txt = abcdef0123456789

## Lessons Learned
* Use multiple tools

## Official Walkthrough
```bash
# walkthrough goes here
```
