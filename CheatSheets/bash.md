<p align="right">
  <a href="/README.md">Home Page</a> |
  <a href="/CheatSheets/bash.md#table-of-contents">Top of Page</a> |
  <a href="/CheatSheets/bash.md#invoke-another-shell">Bottom of Page</a>
</p>

# Cheatsheets - BASH
## Table of Contents
* [Rename Multiple Files](#rename-multiple-files)
* [Invoke Another Shell](#invoke-another-shell)

## Rename Multiple Files
```bash
for FILE in *alpha*; do mv $FILE "${FILE/alpha/beta}"; done
```

## Invoke Another Shell
This example allows you to invoke another shell Without opening another terminal (ex: after updating your .bashrc/.zshrc files).
```bash
exec "$SHELL"
```
