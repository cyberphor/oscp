#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <unistd.h>
 
int main(void) {
  char *binaryPath = "/usr/bin/ping";
  char *arg1 = "-c1";
  char *arg2 = "127.0.0.1";
 
  execl(binaryPath, binaryPath, arg1, arg2, NULL);
  return 0;
}

/* HOW TO COMPILE
gcc foo.c -shared -fPIC -o foo.so
*/
