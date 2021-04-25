## Enumerate
```bash
dirb evil.com -r -z10 # recursive; wait 10 milliseconds between delays

python3 dirsearch/dirsearch.py -u evil.com --simple-report demo-webcrawl.txt

nikto -h evil.com -Format txt -o demo-vulnscan-web.txt
```
