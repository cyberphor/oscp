<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/3_explore.md">Top of Page</a> |
  <a href="/CheatSheets/3_explore.md#bottom-of-page">Bottom of Page</a>
</p>

# Explore
## Table of Contents
* [Information to Gather](#information-to-gather)

## Information to Gather
* User context
* Hostname (may reveal the system’s role, naming convention, OS, etc.)
* OS version (to develop accurate kernel exploits)
* Kernel version (to exploit the core of the OS)
* System architecture (to develop accurate kernel exploits)

## Windows
```bash
whoami # print my current user context
net user victor # print my group memberships, password policy, etc.   
net user # print other accounts on this system
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

## Linux
```bash
whoami # output shows your current user context
id # print my current user context, uid, and gid
cat /etc/passwd # print other accounts on this system
hostname
cat /etc/issue # print OS version
cat /etc/*-release # print OS version
uname -a # print kernel version and system architecture
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/3_explore.md">Top of Page</a> |
  <a href="/CheatSheets/3_explore.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
