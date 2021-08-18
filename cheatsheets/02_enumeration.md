# Enumeration
## Table of Contents
* [Overview](#overview)
* [FTP](#ftp)
* [SSH](#ssh)
* [SMTP](#smtp)
* [HTTP](#http)
* [POP3](#pop3)
* [NFS](#nfs)
* [RPC](#rpc)
* [SMB](#smb)
* [IRC](#irc)
* [Rsync](#rsync)

### Overview
| Port | Protocol | Provides |
| ---- | -------- | -------- |
| 21   | FTP      | Credentials, File upload |
| 22   | SSH      | Remote access |
| 25   | SMTP     | Code execution, Credentials |
| 80   | HTTP     | Code execution, Credentials |
| 110  | POP3     | Code execution, Credentials |
| 111  | NFS      | Credentials |
| 135  | RPC      | Enumeration |
| 445  | SMB      | Credentials, Remote access |
| 873  | Rsync    | File upload |
| 6667 | IRC      | Credentials |

```bash
mkdir scans
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$TARGET-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$TARGET-nmap-complete
sudo nmap $TARGET -sV -sC -p$PORTS -oN scans/$TARGET-nmap-versions
```

### FTP
```bash
ftp $TARGET
# anonymous
# password
pwd

ls
get file.exe

binary
put reverse-shell.exe

exit
```

### SSH
```bash
# technique goes here
```

### SMTP
Manual enumeration
```bash
telnet $TARGET 25
HELO
VRFY root
QUIT
```

Automated enumeration via Nmap.
```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-script-smtp-commands
sudo nmap $TARGET -p25 --script smtp-enum-users -oN scans/$NAME-nmap-script-smtp-enum-users
```

Automated SMTP user enumeration via smtp-user-enum.
```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $TARGET
```

### HTTP
#### Dirb
```bash
dirb $TARGET -r -z10 # recursive; wait 10 milliseconds between delays
```

#### Dirsearch
```bash
sudo apt install dirsearch
dirsearch -u $TARGET -o /home/victor/pwk/labs/$TARGET/scans/$TARGET-dirsearch --format=simple
```

#### Nikto
```bash
nikto -h $TARGET -maxtime=30s -o scans/$TARGET-nikto-30seconds.txt
nikto -h $TARGET -T 2 # scan for misconfiguration vulnerabilities
nikto -h $TARGET -T 9 # scan for SQL injection vulnerabilities
```

```bash
# Tuning (-T) Options
0 – File Upload
1 – Interesting File / Seen in logs
2 – Misconfiguration / Default File
3 – Information Disclosure
4 – Injection (XSS/Script/HTML)
5 – Remote File Retrieval – Inside Web Root
6 – Denial of Service
7 – Remote File Retrieval – Server Wide
8 – Command Execution / Remote Shell
9 – SQL Injection
a – Authentication Bypass
b – Software Identification
c – Remote Source Inclusion
x – Reverse Tuning Options (i.e., include all except specified)
```

### POP3 
```bash
telnet $TARGET 110
USER root
PASS root
RETR 1
QUIT
```

### NFS
```bash
sudo nmap $TARGET -p111 --script-nfs* 
showmount -e $TARGET 

sudo mkdir /mnt/FOO
sudo mount //$TARGET:/$SHARE /mnt/FOO

sudo adduser demo
sudo sed -i -e 's/1001/5050/g' /etc/passwd
cat /mnt/FOO/loot.txt
```

### RPC
```bash
rpcclient -U '' $TARGET
netshareenum # print the real file-path of shares; good for accurate RCE
```

### SMB
SMBClient
```bash
smbclient -L //$TARGET/ # list shares
smbclient -L //$TARGET/ -p $PORT # specify non-standard SMB/Samba port
```

smbget
```bash
smbget -R smb://$TARGET/$SHARE
```

SMBMap
```bash
smbmap -H $TARGET
```

### Rsync
```bash
sudo nmap $TARGET -p873 --script rsync-list-modules
rsync -av rsync://$TARGET/$SHARE --list-only
rsync -av rsync://$TARGET/$SHARE loot
```

### IRC
```bash
irssi -c $TARGET -p $PORT
```