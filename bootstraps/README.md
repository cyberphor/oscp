## Bootstraps

### Code
* add-new-windows-admin.c
  * Boiler-plate C code for a Windows-based exploit.
* katz2crack.py
  * Converts a Mimikatz LSA dump file to a file easily parsed by John the Ripper, Hashcat, etc.
* new-ctf.sh
  * Create a directory, put the following sub-directories/files inside of it: exploits, loot, scans, screenshots, README.md (report) and change where screenshots are saved via my "save-screenshots-here" Python script (see below).
* bytearray.py
  * Prints all possible hexadecimal characters (format: "\x00\x01...")
* print-open-ports-from-nmap-scan.py
  * Prints the TCP and UDP ports found open by Nmap. Intended to make it easier to copy/paste into an Nmap service version detection scan.
* supply-drop.sh
  * Download and install my preferred tools to personalize a new Kali install.
* save-screenshots-here.py
  * Sets the default directory for xfce4-screenshooter.
* system-call-via-execl.c
  * Boiler-plate C code to execute a system call (Linux command) using the execl C function.
* system-call-via-system.c
  * Boiler-plate C code to execute a system call (Linux command) using the system C function.
* vulnerable2bof.c
  * C code vulnerable to a Buffer Overflow.

### References
Exploits
- https://root4loot.com/post/eternalblue_manual_exploit/

Local File Inclusions
- https://www.techsec.me/2020/09/local-file-inclusion-to-rce.html
- https://packetstormsecurity.com/files/89823/vtiger-CRM-5.2.0-Shell-Upload.html

SQL Injection
- http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- https://pentesterlab.com/exercises/from_sqli_to_shell/course
- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#StackingQueries
- https://www.w3schools.com/tags/ref_urlencode.ASP

Windows
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#user-enumeration

Exam Tips
- https://markeldo.com/how-to-pass-the-oscp/
- https://fareedfauzi.gitbook.io/oscp-notes/
- https://github.com/wwong99/pentest-notes/blob/master/oscp_resources/OSCP-Survival-Guide.md
- https://guide.offsecnewbie.com/

Tools
- https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/

Walkthroughs
- https://www.trenchesofit.com/
