#!/usr/bin/env python3
"""Simple Crackme by raxer.

Thirteen characters, and the key material is the program's own machine code:

    lea rax, [rip - 7]        ; rax = 0x400418, this very instruction
    mov rsi, rax
    ...
    lea r8, [0x400262]        ; an eight byte table, "BGOTHXIY"
    loop:
      dl = input[i]
      ecx = code[0x400418 + i] & 7
      cmp dl, table[ecx]
      jne fail
    cmp rax, 0xd              ; thirteen of them
    cmp byte [buf + 13], 0    ; and nothing after

So password[i] = table[code[i] & 7], where `code` is the thirteen bytes the
`lea` points at, which is the instruction that loads the pointer in the first
place. Patch any of those bytes and the password changes with them, which is
what the author means by "no bytepatching".
"""
import sys
from pathlib import Path

CODE_VA, TABLE_VA, LENGTH = 0x400418, 0x400262, 13


def _read(path, va, n):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
    from ucload import parse_image
    for base, data in parse_image(path)['chunks']:
        if base <= va < base + len(data):
            return data[va - base:va - base + n]
    raise KeyError(hex(va))


def password(path='crack_me.exe') -> bytes:
    code = _read(path, CODE_VA, LENGTH)
    table = _read(path, TABLE_VA, 8)
    return bytes(table[c & 7] for c in code)


if __name__ == '__main__':
    p = sys.argv[1] if len(sys.argv) > 1 else str(
        Path(__file__).resolve().parent / 'crack_me.exe')
    print(f'key bytes: {_read(p, CODE_VA, LENGTH).hex(" ")}')
    print(f'table    : {_read(p, TABLE_VA, 8).decode()}')
    print(f'password : {password(p).decode()}')
