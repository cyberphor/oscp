#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char BUFFER[64];

    if (argc <2) {
        printf("[x] Error: You must provide at least one argument.\n");
        return 1; 
    }
    
    strcpy(BUFFER, argv[1]);
    printf(BUFFER);
    printf("\n");
}
