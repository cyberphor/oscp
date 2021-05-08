## BASH
Rename multiple files in your current working directory.
```bash
for FILE in *alpha*; do mv $FILE "${FILE/alpha/beta}"; done
```
