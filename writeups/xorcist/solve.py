#!/usr/bin/env python3
"""XORcist by S3c_Cult.

"Control Flow Obfuscation, XOR encryption and anti-debugging" - and the source
is helpfully shipped alongside, but the encrypted password lives in the binary
so it can be recovered without trusting the .c at all:

    validate(): strcpy(temp, enc); decrypt(temp); return strcmp(input, temp) == 0
    decrypt():  for each byte  b ^= 0xA9

The 14 bytes at 0x2023 xored with 0xA9 spell the password. The rand()/srand()
and useless_branch noise in main is the "obfuscation"; none of it feeds the
check.

    python3 solve.py [xorcist]      recover the password from the binary
"""
import sys
from pathlib import Path

ENC_VA, KEY = 0x2023, 0xA9


def password(path='xorcist') -> str:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
    from ucload import parse_image
    for base, data in parse_image(path)['chunks']:
        if base <= ENC_VA < base + len(data):
            raw = data[ENC_VA - base:]
            enc = raw[:raw.index(0)]
            return bytes(b ^ KEY for b in enc).decode('latin1')
    raise KeyError


if __name__ == '__main__':
    p = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / 'xorcist')
    print(f'password: {password(p)}')
