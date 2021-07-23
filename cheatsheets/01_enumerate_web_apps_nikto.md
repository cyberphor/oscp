<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/enumerate_web_apps_nikto.md#">Top of Page</a> |
  <a href="/CheatSheets/enumerate_web_apps_nikto.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Web Apps
## Nikto
```bash
nikto -h $TARGET -T 2
```
```bash
nikto -h $TARGET -maxtime=60s -o scans/$TARGET-nikto-60seconds.txt
```
```bash
# Tuning (-T) Options
0 – File Upload
1 – Interesting File / Seen in logs
2 – Misconfiguration / Default File
3 – Information Disclosure
4 – Injection (XSS/Script/HTML)
5 – Remote File Retrieval – Inside Web Root
6 – Denial of Service
7 – Remote File Retrieval – Server Wide
8 – Command Execution / Remote Shell
9 – SQL Injection
a – Authentication Bypass
b – Software Identification
c – Remote Source Inclusion
x – Reverse Tuning Options (i.e., include all except specified)
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/enumerate_web_apps_nikto.md#">Top of Page</a> |
  <a href="/CheatSheets/enumerate_web_apps_nikto.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
