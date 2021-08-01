# Penetration Testing Cheatsheet

```bash
sudo nmap $TARGET -sS -sU -oN scans/$TARGET-nmap-initial
```

```bash
sudo nmap $TARGET -sS -sU -p- -oN scans/$TARGET-nmap-complete
```

```bash
sudo nmap $TARGET -sV -sC $(print-open-nmap-ports scans/$TARGET-nmap-complete) -oN scans/$TARGET-nmap-versions
```
