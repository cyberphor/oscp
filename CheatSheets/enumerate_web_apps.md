<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/enumerate_web_apps.md">Top of Page</a> |
  <a href="/CheatSheets/enumerate_web_apps.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Web Apps
## Dirb
```bash
dirb $TARGET -r -z10 # recursive; wait 10 milliseconds between delays
```

## Dirsearch
```bash
sudo apt install dirsearch
dirsearch -u $TARGET -o /home/victor/pwk/labs/$TARGET/scans/$TARGET-dirsearch --format=simple
```

## Nikto
```bash
nikto -h $TARGET -maxtime=30s -o scans/$TARGET-nikto-30seconds.txt
nikto -h $TARGET -T 2 # scan for misconfiguration vulnerabilities
nikto -h $TARGET -T 9 # scan for SQL injection vulnerabilities
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/enumerate_web_apps.md">Top of Page</a> |
  <a href="/CheatSheets/enumerate_web_apps.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
