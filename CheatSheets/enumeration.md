<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/enumeration.md#cheatsheets-enumeration">Top of Page</a> |
  <a href="/CheatSheets/enumeration.md#smb">Bottom of Page</a>
</p>

# Cheatsheets - Enumeration
## Table of Contents
* [Priority of Work](#priority-of-work)
* [Nmap](#nmap)
* [FTP](#ftp)
* [NFS](#nfs)
* [SMTP](#smtp)
* [SMB](#smb)

## Priority of Work
|Priority|Protocol|Port|Provides|
|--------|--------|----|--------|
|1       |TCP     |80  |Code execution|

## Nmap
```bash
mkdir nmap
sudo nmap $TARGET -sS -sU --min-rate 1000 -oA nmap/$TARGET-initial
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oA nmap/$TARGET-complete
sudo nmap $TARGET -sS -sU -p$PORTS -oA nmap/$TARGET-versions
```

## FTP
TCP Port 21
```bash
ftp $TARGET
# anonymous
# password
pwd
ls
get file.exe
exit
```

## NFS
TCP Port 111
```bash
sudo nmap $TARGET -p111 --script-nfs* 
showmount -e $TARGET 

sudo mkdir /mnt/FOO
sudo mount //$TARGET:/$SHARE /mnt/FOO

sudo adduser demo
sudo sed -i -e 's/1001/5050/g' /etc/passwd
cat /mnt/FOO/loot.txt
```

## SMTP
TCP Port 25
```bash
telnet $TARGET 25
HELO
VRFY root
QUIT
```

## SMB
Impacket SMB Client
```bash
impacket-smbclient ''@$TARGET
use IPC$
```
SMBClient
```bash
smbclient -L //10.11.1.5/ # list shares
```
