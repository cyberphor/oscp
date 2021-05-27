<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/bash.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/bash.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - BASH
## Table of Contents
* [Create a Command Alias](#create-a-command-alias)
* [Rename Multiple Files](#rename-multiple-files)
* [Invoke Another Shell](#invoke-another-shell)
* [Send Multiple Files via SSH](#send-multiple-files-via-ssh)
* [Download Multiple Files Using Wget](#download-multiple-files-using-wget)
* [Keyboard Shortcuts](#keyboard-shortcuts)

## Create a Command Alias
**Interactive Shells** (the CLI, a.k.a terminal)  
Zsh
```bash
echo "alias cls='cls'" >> .zshrc # just me
echo "alias cls='cls'" >> /etc/zsh/zshrc # for all users
```
BASH
```bash
echo "alias cls='cls'" >> .bash_aliases # just me
echo "alias cls='cls'" >> /etc/bash.bashrc # for all users
```

**Login Shells (the GUI)**
```bash
echo "alias cls='cls'" >> .profile # just me
echo "alias cls='cls'" >> /etc/profile # for all users
```

## Environment Variables
**PS1**
```bash
# how to change it to the previously less flashy one
vim .bashrc
# search for PS1 using /PS1
# comment-out PS1=$prompt_color...
# un-comment the line beneath BackTrack red prompt
```

**Shell**
```nash
# how to change it from Zsh to BASH
chsh -s /bin/bash
sudo reboot now
```

## Rename Multiple Files
```bash
for FILE in *alpha*; do mv $FILE "${FILE/alpha/beta}"; done
```

## Invoke Another Shell
This example allows you to invoke another shell Without opening another terminal (ex: after updating your .bashrc/.zshrc files).
```bash
exec "$SHELL"
```

## Send Multiple Files via SSH
```bash
scp -r software/ victor@$TARGET:~/
```

## Download Multiple Files Using Wget
```bash
wget -r http://$TARGET/$FOLDER -O $FOLDER
```

## Keyboard Shortcuts
```bash
CTRL+E # jump to end of line
CTRL+A # jump to beginning of line
CTRL+X+DEL # delete all text typed, from right to left
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/bash.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/bash.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
