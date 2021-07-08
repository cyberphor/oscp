#!/bin/bash

if [ -z $1  ]; then
  echo "new-ctf <ctf_name>"
else
  mkdir $1
  cd $1
  mkdir exploits loot scans screenshots
  sudo save-screenshots-here ./screenshots 
  wget https://raw.githubusercontent.com/cyberphor/pwk/main/ReportTemplates/draft-report.md
  wget https://raw.githubusercontent.com/cyberphor/pwk/main/ReportTemplates/final-report.md
  ls -al
fi
