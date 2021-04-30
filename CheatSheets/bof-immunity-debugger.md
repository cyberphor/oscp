# Cheatsheet - Buffer Overflows (BOF)
## Immunity Debugger
```bash
File > Open # open a program for debugging; provide file name & arguments
Debug > Step into # follow the execution flow of a function
Debug > Step over # execute a function and return from it

# how to find and proceed to the Main function of a program
- [Right-click Assembly pane] > Search for > All referenced text strings
- Double-click on the correct result (and return to the Assembly pane)
- Highlight the text of interest (ex: strcpy) & press F2 (set a breakpoint)
- Debug > Run (execution will stop just before your breakpoint)
- Debug > Step into # watch program execution "frame by frame"
```
