#!/usr/bin/env python

import os

def check_creds():
    print("[x] This script requires administrator privileges.")

def edit_smb_conf():
    with open("/etc/samba/smb.conf") as smb:
        v1 = "client min protocol"
        conf = smb.readlines()
        for line in conf:
            if v1 in line:
                print(line).rstrip()
    enable = v1 + " = 1"
    disable =  "# " + v1

def restart_smbd():
    os.system("sudo service smbd restart")
    print("[+] Restarted smbd.")

if __name__ == "__main__":
    check_creds()
    edit_smb_conf()
    #restart_smbd()
