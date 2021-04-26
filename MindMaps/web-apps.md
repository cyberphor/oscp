# Mind Map - Web Apps
## Enumerate 
* Enumerate the following before attempting to exploit a web app:
  * Programming language and/or web development framework in use
  * Web server software in use
  * Database software in use
  * Server operating system in use
* URLs
  * Filetype extensions (don't forget, modern web apps might use routes instead)
* Web Page Source Code
  * Comments
  * Hidden form fields
* Response Headers
  * Server header
  * "X-" headers
* Site Maps
  * robots.txt
  * sitemap.xml
* Admin Consoles
  * MySQL
    * Tomcat:
      * Path: /manager/html
    * phpMyAdmin:
      * Path: /phpmyadmin
      * Configuration file: config.inc.php

## Exploit
* Admin Consoles
  * Attempt to login using default credentials
  * Attempt to login using credentials found elsewhere (shares: SMB, NFS, etc.)
  * Use Burp Proxy to confirm which parameters are required to submit a valid HTTP request (cookie, session, password, token, etc.)
  * Use Burp Intruder to set the parameters required to submit a valid HTTP request
* XSS
  * Check if special characters are sanitized: <, >, {, }, ', ", ;
  * Check if HTML encoded special characters are sanitized  
  * Check if URL (Percent) encoded special characters are sanitized
  * Attempt a XSS attack 
    * Redirect a victim to a staged, information gathering script (HTML iframes)
    * Steal cookies and use them to negate having to authenticate to an Admin Console (JavaScript)
* Directory Traversal
  * Find references to files and change the value to something else. 
  * Look for file extensions in URLs. 
  * If you find a viable attack vector, try files accessible by all users (try the paths using encoding too; consider null characters to terminate file paths).
    * Windows:
      * C:\boot.ini
      * C:\Windows\System32\Drivers\etc\hosts
    * Linux:
      * /etc/passwd 
  * If you're able to access the web app's configuration files (ex: php.ini), you might be able to find credentials or determine if File Inclusions are allowed. 
    * Variables to check in the php.ini configuration file. 
      * register_globals
      * allow_url 
* File Inclusions

## Explore
* Admin Consoles
  * Explore accessible databases
    * Determine their design (tables, columns, rows)
    * Read their contents

## Effect
* Admin Consoles
  * Add accounts to maintain access 
