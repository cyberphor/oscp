#!/usr/bin/env python

import argparse

def update_flameshot_config(directory):
    config_file_path = "/home/victor/.config/flameshot/flameshot.ini"
    savePath = "savePath="
    savePath_default = savePath + "/home/victor/Pictures\n"
    savePath_new = savePath + directory + "\n"
    with open(config_file_path,"r") as config_file:
        config = config_file.readlines()
        settings = []
        for setting in config:
            if savePath in setting:
                settings.append(savePath_new)
            else:
                settings.append(setting)
        new_config = ''.join(settings)
    print(new_config)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d")
    args = parser.parse_args()
    if args.d:
        update_flameshot_config(args.d)

if __name__ == "__main__":
    main()
