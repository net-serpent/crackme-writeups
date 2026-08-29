#!/usr/bin/env python3
"""Simple Keygen by Yuri.

checkSerial wants a 16-byte serial made of eight consecutive-character pairs:

    strlen(s) == 16
    for i in 0, 2, 4, ... 14:
        s[i] - s[i+1] == -1        # i.e. s[i+1] == s[i] + 1

Every even byte is one less than the byte after it, nothing else is checked.

    python3 solve.py            a valid serial
    python3 solve.py SEED       build one from an 8-char seed
"""
import sys


def serial(seed: str = 'ABCDEFGH') -> str:
    seed = (seed * 8)[:8]
    return ''.join(f'{c}{chr((ord(c) + 1) & 0x7F)}' for c in seed)


def check(s: str) -> bool:
    b = s.encode()
    return len(b) == 16 and all((b[i] - b[i + 1]) & 0xFF == 0xFF for i in range(0, 16, 2))


if __name__ == '__main__':
    s = serial(sys.argv[1] if len(sys.argv) > 1 else 'ABCDEFGH')
    print(f'serial: {s}   valid={check(s)}')
