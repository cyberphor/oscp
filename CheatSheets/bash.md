## BASH
Rename multiple files in your current working directory.
```bash
for FILE in *alpha*; do mv $FILE "${FILE/alpha/beta}"; done
```

Invoke a shell without opening another terminal (ex:after updating your .bashrc/.zshrc files)
```bash
exec "$SHELL"
```
