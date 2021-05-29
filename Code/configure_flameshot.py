#!/usr/bin/env python

import argparse
import os

def update_flameshot_config(config_file_path,save_path,save_dir):
    with open(config_file_path,"r") as config_file:
        config = config_file.readlines()
        settings = []
        for setting in config:
            if save_path in setting:
                settings.append(save_path + save_dir + "\n")
            else:
                settings.append(setting)
        new_config = ''.join(settings)
    print(new_config)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir")
    parser.add_argument("--reset",action="store_true")
    args = parser.parse_args()
    user_home = os.path.expanduser("~")
    user = os.path.split(user_home)[-1]
    config_file_path = user_home + "/.config/flameshot/flameshot.ini"
    save_path = "savePath="
    if args.d:
        save_dir = args.d
    elif args.reset:
        save_dir = user_home + "/Pictures"
    else:
        exit()
    update_flameshot_config(config_file_path,save_path,save_dir)

if __name__ == "__main__":
    main()
