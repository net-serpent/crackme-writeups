#!/usr/bin/env python3
"""crackme_2.0_find_the_secret_text by devoney.

There is no comparison anywhere in this one. The dialog handler takes each
character you type and scatters it, with a per-character constant added, over a
19 byte template in .data that starts life as "1234567890123456789". Then:

    WriteProcessMemory(GetCurrentProcess(), 0x401351, template, 19, NULL)

0x401351 is the run of NOPs immediately after that call, so the program
overwrites its own next instructions with bytes derived from your input and
executes them. Type the right thing and those 19 bytes assemble into a
MessageBoxA call.

Every one of the 19 positions is written by exactly one input character, and
always as `out = in + constant`, which makes the whole thing invertible: pick
the code you want, read the input straight off it.

    python3 solve.py            the password and the shellcode it builds
"""

PATCH_AT, THUNK = 0x401351, 0x401396          # NOP sled, MessageBoxA thunk
TEXT, CAPTION = 0x403025, 0x40303F            # the two strings in .data
LENGTH = 19

# which input character owns each output byte, and what it adds
OWNER = {0: 1, 1: 0, 2: 2, 3: 6, 4: 3, 5: 4, 6: 0, 7: 2, 8: 7, 9: 3,
         10: 4, 11: 0, 12: 1, 13: 0, 14: 5, 15: 8, 16: 0, 17: 0, 18: 0}
DELTA = {0: 0x0B, 1: 0xA5, 2: 0x25, 3: 0xD4, 4: 0xBE, 5: 0xDF, 6: 0xA5,
         7: 0x25, 8: 0xC6, 9: 0xBE, 10: 0xDF, 11: 0xA5, 12: 0x0B, 13: 0xA5,
         14: 0x85, 15: 0xD5, 16: 0xA5, 17: 0xA5, 18: 0xA5}


def shellcode() -> bytes:
    """push 0 / push caption / push text / push 0 / call MessageBoxA"""
    rel = THUNK - (PATCH_AT + LENGTH)
    return bytes([0x6A, 0x00,
                  0x68, CAPTION & 0xFF, 0x30, 0x40, 0x00,
                  0x68, TEXT & 0xFF, 0x30, 0x40, 0x00,
                  0x6A, 0x00,
                  0xE8] + list(rel.to_bytes(4, 'little')))


def password() -> bytes:
    code = shellcode()
    pw = bytearray(9)
    for off, idx in OWNER.items():
        pw[idx] = (code[off] - DELTA[off]) & 0xFF
    return bytes(pw)


def build(pw: bytes) -> bytes:
    """What the handler would assemble from this input."""
    return bytes((pw[OWNER[o]] + DELTA[o]) & 0xFF for o in range(LENGTH))


if __name__ == '__main__':
    pw = password()
    print(f'password: {pw.decode()}')
    print(f'builds  : {build(pw).hex(" ")}')
    print(f'matches : {build(pw) == shellcode()}')
    print('secret  : greed')
