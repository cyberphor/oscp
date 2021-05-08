sudo apt install tree -y
echo "[+] Installed: tree"

git clone https://github.com/maurosoria/dirsearch
sudo cp -R ./dirsearch/ /usr/local/bin/dirsearch/

#SHELL=$(env | grep 'SHELL=' | cut -d'=' -f2)
#if [ $SHELL == '/bin/bash' ]; then
#    echo 'export PATH=$PATH:/usr/local/bin/dirsearch' >> ~/.bashrc
#elif [ $SHELL == '' ]; then
#    echo 'export PATH=$PATH:/usr/local/bin/dirsearch' >> ~/.bashrc
#    echo 'zsh'
#fi
echo "[+] Installed: dirsearch"
