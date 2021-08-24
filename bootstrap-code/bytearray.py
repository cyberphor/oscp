#!/usr/bin/env python3

ARRAY = []
for x in range(1, 256):
    BYTE = ("\\x" + "{:02x}".format(x))
    ARRAY += BYTE
BYTEARRAY = ''.join(ARRAY)
print(BYTEARRAY)
