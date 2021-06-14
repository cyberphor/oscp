#include <stdlib.h>

int main(void) {
  int system(const char *command);
  system("cat /etc/passwd");
  system("ping -c1 localhost");
  return 0;
}

/* HOW TO COMPILE
gcc foo.c -shared -fPIC -o foo.so
*/
