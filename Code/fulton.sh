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
