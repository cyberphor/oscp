#!/usr/bin/env python

hex_chars =[]
for integer in range(0, 256):
    hex_char = str(hex(integer))
    if len(hex_char) == 3:
        hex_chars += hex_char.replace('0x','\\x0')
    else:
        hex_chars += hex_char.replace('0x','\\x')

all_possible_hex_chars = ''.join(hex_chars)
print(all_possible_hex_chars)
