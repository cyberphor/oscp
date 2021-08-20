#!/bin/bash

if [ -z $1  ]; then
  echo "new-ctf <ctf_name>"
else
  mkdir $1
  cd $1
  mkdir exploits loot scans screenshots
  sudo save-screenshots-here ./screenshots 
  wget https://raw.githubusercontent.com/cyberphor/pwk/main/report/README.md
  wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -O exploits/lse.sh
  ls -al
fi
