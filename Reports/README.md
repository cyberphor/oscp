# Template
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh) 
    * [FTP](#ftp)
    * [SMTP](#smtp)
    * [DNS](#dns)
    * [HTTP](#http)
    * [POP3](#pop3)
    * [RPC](#rpc)
    * [IMAP](#imap)
    * [NetBIOS](#netbios)
    * [SMB](#smb)
    * [SQL](#sql)
    * [RDP](#rdp)
  * [OS](#os)
* [Exploit](#exploit)
  * [Online Password Guessing](#online-password-guessing)
  * [Offline Password Guessing](#offline-password-guessing)
* [Explore](#explore)
* [Escalate](#escalate)
* [Effect](#effect)
* [Lessons Learned](#lessons-learned)

## Summary
* Hostname: 
* IP address: 
* MAC address: (ref:)
* Domain: 
* TCP Ports and Services
  * 22
    * ???
  * 80
    * ???
  * 445
    * ???
* UDP Ports and Services
  * 53
* OS
  * Distro: (ref:)
  * Kernel: (ref:)
  * Architecture: (ref:)
* Users (ref: )
  * ???
* Vulnerabilities
  * CVE-??? (ref:)
* Exploits
  * ??? (ref:)
* Flag
  * ???
* Hints
  * n/a

# Enumerate
```bash
TARGET=10.11.12.13
NAME=demo
mkdir $NAME
mkdir $NAME/exploits
mkdir $NAME/loot
mkdir $NAME/scans
mkdir $NAME/screenshots
sudo save-screenshots-here $NAME/screenshots
cd $NAME
```

## Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
sudo nmap $TARGET -sV $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions

# output
NSTR
```

## Services
### FTP
```bash
???
```

### SSH
```bash
???
```

### SMTP
Automated enumeration of supported SMTP commands.
```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-script-smtp-commands
```

Automated enumeration of existing SMTP users.
```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$NAME-nmap-script-smtp-enum-users
```
```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $TARGET
```

Automated enumeration of exploitable SMTP vulnerabilities.
```bash
sudo nmap $TARGET -p25 --script smtp-vuln* -oN scans/mailman-nmap-script-smtp-vuln
```

## DNS
```bash
???
```

### HTTP
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch --format=simple
dirsearch -u $TARGET:$PORT -e php -o $FULLPATH/$NAME-dirsearch-php --format=simple

# output
NSTR
```
```bash
dirb http://$TARGET -r -z10 -o scans/$NAME-dirb-common

# output
NSTR
```
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
NSTR
```
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock

# output
NSTR
```

### RPC
```bash
rpcclient -U '' $TARGET

# output
NSTR
```

### NetBIOS
```bash
nbtscan $TARGET

# output
NSTR
```

### SMB
```bash
smbclient -L $TARGET

# output
NSTR
```
```bash
smbmap -H $TARGET

# output
NSTR
```
```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010

# output
NSTR
```
```bash
# check if vulnerable to SambaCry
sudo nmap $TARGET -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-smb-vuln-cve-2017-7494

# output
NSTR
```

### SQL
```bash
mysql -u $USER -h $TARGET

# output
NSTR
```

### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-script-rdp-ntlm-info

# output
NSTR
```
```bash
rdesktop -u administrator $TARGET
```

## OS
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os

# output
NSTR
```

# Exploit
## Online Password Guessing
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"

# output
NSTR
```

## Offline Password Guessing
Hashcat
```bash
hashcat -m 1000 -a 0 --force --show $HASHDUMP /usr/share/wordlists/rockyou.txt 
```

John the Ripper
```bash
unshadow $PASSWD_FILE $SHADOW_FILE > $HASHDUMP
john $HASHDUMP --wordlist=/usr/share/wordlists/rockyou.txt
```

# Explore

# Escalate

# Effect

# Lessons Learned
