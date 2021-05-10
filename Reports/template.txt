# Template
## Table of Contents
* [Enumerate](#enumerate)
* [Exploit](#exploit)
* [Explore](#explore)
* [Escalate](#escalate)
* [Effect](#effect)

## Enumerate
```bash
TARGET=
```
```bash
sudo nmap $TARGET -sS -sU --min-rate 1000 -oA $TARGET-initial
```
```bash
sudo nmap $TARGET -sS -sU -p- --min-rate 1000 -oA $TARGET-complete
```
```
sudo nmap $TARGET -pT:80,U:53 -oA $TARGET-versions
```

## Exploit

## Escalate

## Explore
