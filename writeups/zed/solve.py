#!/usr/bin/env python3
"""ZED-Crackme. UPX packed, and behind the packer almost everything is a decoy.

The binary ships checkSerial, cryptSerial, gauss_eliminate, generic_fizz_buzz,
obfuscation, swap_row and compare. Cross-reference them and only `rot` is ever
called, twice with 13, which is the identity. Gaussian elimination, fizzbuzz
and the qsort comparator are all unreachable.

The real check is twenty lines at the end of main. A 19 byte string is built on
the stack, mangled, and strcmp'd against what you type:

    s[0] = M[0] ^ 2
    s[1] = M[3] - 10
    s[2] = M[2] + 12
    s[3] = M[2]
    s[4] = M[1] + 1
    s[i] = M[i] - 1        for i in 5..18
"""
MAGIC = b'AHi23DEADBEEFCOFFEE'


def serial(m: bytes = MAGIC) -> bytes:
    out = bytearray(len(m))
    out[0] = (m[0] ^ 2) & 0xFF
    out[1] = (m[3] - 10) & 0xFF
    out[2] = (m[2] + 12) & 0xFF
    out[3] = m[2]
    out[4] = (m[1] + 1) & 0xFF
    for i in range(5, 19):
        out[i] = (m[i] - 1) & 0xFF
    return bytes(out)


if __name__ == '__main__':
    print(f'magic  {MAGIC.decode()}')
    print(f'serial {serial().decode()}')
