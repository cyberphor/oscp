#!/usr/bin/env python

import argparse
import os
import sys

def update_screenshooter(config_file_path,delimiter,screenshot_dir):
    with open(config_file_path,"r") as config:
        old_config = config.readlines()
        new_settings = []
        for setting in old_config:
            if delimiter in setting:
                new_settings.append(delimiter + screenshot_dir + "\n")
            else:
                new_settings.append(setting)
        new_config = ''.join(new_settings)
        print("[+] xfce4-screenshooter configuration:")
        print(new_config)
    with open(config_file_path,"w") as config:
        config.write(new_config)

def main():
    home_dir = os.path.expanduser("~")
    config_file_path = home_dir + "/.config/xfce4/xfce4-screenshooter"
    delimiter = "screenshot_dir=file://"
    if len(sys.argv) > 1:
        if sys.argv[1] == "--reset":
            screenshot_dir = home_dir + "/Pictures"
        else:
            screenshot_dir = os.path.realpath(sys.argv[1])
    update_screenshooter(config_file_path,delimiter,screenshot_dir)

if __name__ == "__main__":
    main()
