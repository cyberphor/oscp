# Mind Map - Web Apps
Attempt to enumerate the following before attempting to exploit a web app:
* Programming language and/or web development framework in use
* Web server software in use
* Database software in use
* Server operating system in use

## Enumerate 
* URLs
  * Filetype extensions (beware: routes)
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
