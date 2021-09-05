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
dirb http://$TARGET 
dirb http://$TARGET:$PORT/ -o scans/$TARGET-dirb-$PORT-common
dirb http://$TARGET:$PORT/ /usr/share/wordlist/dirb/big.txt -o scans/$TARGET-dirb-$PORT-big
```

#### Dirsearch
```bash
dirsearch -u $TARGET -o /home/victor/oscp/pwk/labs/$TARGET/scans/$TARGET-dirsearch-$PORT-$WORDLIST 
```

#### Nikto
```bash
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
smbget -R smb://$TARGET:$PORT/$SHARE
```

SMBMap
```bash
smbmap -H $TARGET
smbmap -H $TARGET -P $PORT
```

#### WinRM
```bash
evil-winrm -u $USER -p $PASSWORD -i $TARGET
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