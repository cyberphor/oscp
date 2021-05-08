#!/usr/bin/env python3

import argparse
import re

def get_open_ports(filename):
    with open(filename) as scan:
        tcp_ports = []
        udp_ports = []
        for line in scan.readlines():
            if re.search("/tcp",line):
                tcp_ports.append(line.split("/")[0])
            elif re.search("/udp",line):
                udp_ports.append(line.split("/")[0])
        open_tcp_ports = "T:" + ",".join(tcp_ports)
        open_udp_ports = "U:" + ",".join(udp_ports)
        if tcp_ports and udp_ports:
            print("-p" + open_tcp_ports + "," + open_udp_ports)
        elif tcp_ports:
            print("-p" + open_tcp_ports)
        elif udp_ports:
            print("-p" + open_udp_ports)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f")
    args = parser.parse_args()
    if args.f:
        get_open_ports(args.f)

if __name__ == "__main__":
    main()
