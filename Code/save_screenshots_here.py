#!/usr/bin/env python

import os
import re
import sys

def check_credentials():
    if os.geteuid() != 0:
        exit()

def update_screenshooter(screenshot_dir):
    config_file_path = "/usr/share/kali-themes/xfce4-screenshooter"
    with open(config_file_path,"r") as config:
        old_config = config.readlines()
        new_settings = []
        for setting in old_config:
            if "$FILE" in setting:
                if "xdg-user-dir" in setting:
                    pattern = r'\".+\"'
                else:
                    pattern = r"\/\w+"
                if screenshot_dir == "default":
                    update = '"$(xdg-user-dir PICTURES)/$FILE"'
                else:
                    update = screenshot_dir + "/$FILE"
                updated_setting = re.sub(pattern,update,setting)
                new_settings.append(updated_setting)
            else:
                new_settings.append(setting)
        new_config = ''.join(new_settings)
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
