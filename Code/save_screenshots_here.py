#!/usr/bin/env python

import os
import re
import sys

def check_credentials():
    if os.geteuid() != 0:
        exit()

def update_screenshooter(screenshot_dir):
    config_file_path = "/usr/share/kali-themes/xfce4-screenshooter"
    pattern = r"\/.+\$FILE"
    update = screenshot_dir + "/$FILE"
    with open(config_file_path,"r") as config:
        old_config = config.read()
        if "xdg-user-dir" in old_config:
            pattern = r'\"\$\(.+\)\/\$FILE\"'
        if screenshot_dir == "default":
            update = '"$(xdg-user-dir PICTURES)/$FILE"'
        new_config = re.sub(pattern,update,old_config,2)
    with open(config_file_path,"w") as config:
        config.write(new_config)

def main():
    check_credentials()
    if len(sys.argv) > 1:
        if sys.argv[1] == "--reset":
            screenshot_dir = "default"
        else:
            screenshot_dir = os.path.realpath(sys.argv[1])
    update_screenshooter(screenshot_dir)

if __name__ == "__main__":
    main()
