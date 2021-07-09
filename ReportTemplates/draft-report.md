# Report Draft 
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
* Hostname: 
* Description: 
* IP Address: 
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oN scans/$NAME-nmap-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-complete
# replace the lines above with the actual scan
```

### Service Versions
```bash
sudo nmap $TARGET -sV -sC $(print-open-ports-from-nmap-scan scans/$NAME-nmap-complete) -oN scans/$NAME-nmap-versions
# replace the lines above with the actual scan results
```

### Operating System
```bash
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oN scans/$NAME-nmap-os
# replace the lines above with the actual scan results
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
sudo nmap $TARGET -p25 --script smtp-commands -oN scans/$NAME-nmap-script-smtp-commands
```

Automated enumeration of existing SMTP users.
```bash
sudo nmap $TARGET -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} -oN scans/$NAME-nmap-script-smtp-enum-users
```
```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $TARGET
```

Automated enumeration of exploitable SMTP vulnerabilities.
```bash
sudo nmap $TARGET -p25 --script smtp-vuln* -oN scans/mailman-nmap-script-smtp-vuln
```

### HTTP
The target is NOT vulnerable to Shellshock.
```bash
sudo nmap $TARGET -p80 --script http-shellshock -oN scans/$NAME-nmap-scripts-http-shellshock-80

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirb.
```bash
dirb http://$TARGET:80 -w /usr/share/wordlists/dirb/big.txt -z10 -o scans/$NAME-dirb-big-80

# output
NSTR
```

Victor was able to discover the hidden directories below using Dirsearch.
```bash
dirsearch -u $TARGET:$PORT -o $FULLPATH/$NAME-dirsearch-80 --format=simple
dirsearch -u $TARGET:$PORT -e php -o $FULLPATH/$NAME-dirsearch-80-php --format=simple

# output
NSTR
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
NSTR
```

### NetBIOS
```bash
nbtscan $TARGET

# output
NSTR
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
NSTR
```

The SMB shares discovered have the following permissions.
```bash
smbmap -H $TARGET

# output
NSTR
```

The target is NOT vulnerable to EternalBlue.
```bash
# check if vulnerable to EternalBlue
sudo nmap $TARGET -p445 --script smb-vuln-ms17-010 -oN scans/$NAME-nmap-scripts-smb-vuln-ms17-010

# output
NSTR
```

The target is NOT vulnerable to SambaCry.
```bash
# check if vulnerable to SambaCry
sudo nmap $TARGET -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -oN scans/$NAME-nmap-smb-vuln-cve-2017-7494

# output
NSTR
```

### SQL
```bash
mysql -u $USER -h $TARGET

# output
NSTR
```

### RDP
```bash
sudo nmap $TARGET -p3389 --script rdp-ntlm-info -oN scans/$NAME-nmap-script-rdp-ntlm-info

# output
NSTR
```

```bash
rdesktop -u administrator $TARGET
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
#### Default Credentials
```bash
# CMS Web App 9000
# admin:admin
```

#### Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/phpmyadmin/index.php?:pma_username=^USER^&pma_password=^PASS^:Cannot|without"

# output
NSTR
```

#### Patator
```bash
patator http_fuzz url=http://$TARGET/$LOGIN method=POST body='username=FILE0&password=FILE1' 0=usernames.txt 1=/usr/share/wordlists/rockyout.txt -x ignore:fgrep=Unauthorized
```

### CVE-2021-1234
#### EDB-ID-56789
```bash
searchsploit foo
mkdir edb-id-56789
cd edb-id-56789
searchsploit -x 56789
```

#### cyberphor POC
```bash
git clone https://github.com/cyberphor/cve-2021-1234-poc.git
cd cve-2021-56789-poc
```

#### Metasploit Module
```bash
msfconsole
search ???
use exploit/???/???
set LHOST tun0
set RHOST $TARGET
run
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
  * Nmap
  * Patator
  * Intruder from Burp Suite

## Hints
  * Scan all ports
  * Identify every application and their version
  * Try harder

## Flags
* abcdef0123456789

## Official Walkthrough
```bash
# walkthrough goes here
```
