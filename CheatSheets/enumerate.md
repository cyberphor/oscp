## Nmap
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oA demo-initial
```

## NFS
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
