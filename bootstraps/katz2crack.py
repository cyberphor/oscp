#!/usr/bin/env python3

import os
import sys

def convert(filename):
    pairs = []
    with open(filename,'r') as olddump:
        usernames = []
        hashes = []
        for line in olddump.readlines():
            if 'User' in line:
                user = line.rstrip('\n').split(':')[1].lstrip()
                usernames.append(user)
            elif 'NTLM' in line:
                ntlm = line.rstrip('\n').split(':')[1].lstrip()
                hashes.append(ntlm)
        for pair in zip(usernames,hashes):
            pairs.append(':'.join(pair))
    if os.path.isfile('hashes.dump'):
        print('[x] hashes.dump already exists. Exiting...')
    else:
        with open('hashes.dump','a') as newdump:
            print('[+] Created: hashes.dump')
            for pair in pairs:
                newdump.write(pair + '\n')
                print(pair)

if __name__=="__main__":
    filename = sys.argv[1]
    convert(filename)
