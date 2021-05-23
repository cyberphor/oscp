<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/python.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/python.md#bottom-of-page">Bottom of Page</a>
</p>

# Cheatsheets - Python
## Table of Contents
* [Pyenv](#pyenv)
* [Pip](#pip)

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

## Bottom of Page
