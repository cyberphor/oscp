## Enumerate
```bash
dirb evil.com -r -z10 # recursive; wait 10 milliseconds between delays

python3 dirsearch/dirsearch.py -u evil.com --simple-report demo-webcrawl.txt

nikto -h evil.com -Format txt -o demo-vulnscan-web.txt
```
```sql
SELECT * FROM target.users # database.table
```

## Effect
Add a new user to a SQL database
```sql
INSERT INTO target.users(username, password) VALUES ('victor','please');
```
