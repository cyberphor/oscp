<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/openvpn.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/openvpn.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - OpenVPN
## Table of Contents
* [Configuring a Password File](#configuring-a-password-file)

## Configuring a Password File
```bash
echo "victor" >> creds.txt
echo "SuperStrongPassPhrase" >> creds.txt

chmod u+r creds.txt
chmod go-rwx creds.txt

sed '15 i\auth-user-pass creds.txt' pwk-labs.ovpn # insert this line before the 15th line
sudo openvpn pwk-labs.ovpn
```

<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/openvpn.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/openvpn.md#bottom-of-page">Bottom of Page</a>
</p>

## Bottom of Page
