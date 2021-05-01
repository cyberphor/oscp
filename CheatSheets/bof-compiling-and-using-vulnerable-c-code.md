# Cheatsheet - Buffer Overflows (BOF)
## Compiling and Using Vulnerable C Code
How to Invoke the Vim Text-Editor
```bash
vim bof.c
```

Vulnerable C Code
```c
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
```

How to Compile the Code Above
```
gcc bof.c -o bof
```

How to Run the Resulting, Compiled Program (Example 1)
```bash
./bof hello

# output
hello
```

How to Run the Resulting, Compiled Program (Example 2)
```bash
./bof $(printf 'A%.0s' {1..64})

# output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

How to Crash the Resulting, Compiled Program
```bash
./bof $(printf 'A%.0s' {1..72})

# output
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```
