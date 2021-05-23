sudo apt install tree -y
echo "[+] Installed: tree"

sudo apt install burpsuite -y
echo "[+] Installed: Burp Suite"

sudo apt install mdless -y
echo "[+] Installed: mdless"

#git clone https://github.com/maurosoria/dirsearch
#sudo cp -R ./dirsearch/ /usr/local/bin/dirsearch/

#SHELL=$(env | grep 'SHELL=' | cut -d'=' -f2)
#if [ $SHELL == '/bin/bash' ]; then
#    echo 'export PATH=$PATH:/usr/local/bin/dirsearch' >> ~/.bashrc
#elif [ $SHELL == '' ]; then
#    echo 'export PATH=$PATH:/usr/local/bin/dirsearch' >> ~/.bashrc
#    echo 'zsh'
#fi
echo "[+] Installed: dirsearch"

wget https://addons.mozilla.org/firefox/downloads/file/3616824/foxyproxy_standard-7.5.1-an+fx.xpi
firefox ./foxyproxy_standard-7.5.1-an+fx.xpi
echo "[+] Installed: foxyproxy"

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
echo "[+] Installed: pyenv"
echo "[+] Configured: python - to be version 2.7.18"

curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python get-pip.py
python -m pip --version
echo "[+] Installed: pip"
python -m pip install --upgrade setuptools
python -m pip install impacket
echo "[+] Installed: impacket"
python -m pip install pysmb
echo "[+] Installed: pysmb"
python -m pip install pysmbclient
echo "[+] Installed: pysmbclient"
python -m pip install pycryptodome
echo "[+] Installed: pycryptodome"

sudo apt-get install gcc-multilib
echo "[+] Installed: gcc-multilib"
