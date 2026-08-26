#!/usr/bin/env python3
"""recoded_keygenme_1 by recoded.

Serial format is four groups of eight hex digits joined by dashes, 35
characters exactly. The validator walks the string and only accepts hex
digits, plus a dash at every ninth position, which it overwrites with a NUL,
so the buffer turns into four separate hex strings.

Then it runs four rounds. Writing S(m) for

    sum over the name's non-space characters of  ror32(c * m, 19)

the rounds require

    g0 = S(g1)    g1 = S(g2)    g2 = S(g3)    g3 = S(K),   K = 0x4012a2

each checked by subtracting the sum from the group and requiring zero. The
chain is only circular if you read it forwards: the last round has no unknown
on the right, so solve it and walk back up.

    python3 solve.py NAME
"""
import sys

M = 0xFFFFFFFF
SEED = 0x4012A2                    # the constant at 0x403087
MIN_NAME = 4


def ror32(v, n):
    v &= M
    return ((v >> n) | (v << (32 - n))) & M


def digest(name: str, mult: int) -> int:
    total = 0
    for ch in name:
        if ch == ' ':
            continue
        total = (total + ror32((ord(ch) & 0xFF) * mult, 19)) & M
    return total


def serial(name: str) -> str:
    if len(name) < MIN_NAME:
        raise ValueError('the name has to be at least 4 characters')
    g3 = digest(name, SEED)
    g2 = digest(name, g3)
    g1 = digest(name, g2)
    g0 = digest(name, g1)
    return '-'.join(f'{g:08X}' for g in (g0, g1, g2, g3))


def check(name: str, ser: str) -> bool:
    """The validator's own view, for cross-checking."""
    parts = ser.split('-')
    if len(ser) != 35 or len(parts) != 4 or any(len(p) != 8 for p in parts):
        return False
    try:
        g = [int(p, 16) for p in parts]
    except ValueError:
        return False
    mults = g[1:] + [SEED]
    return all(digest(name, m) == g[i] for i, m in enumerate(mults))


if __name__ == '__main__':
    who = sys.argv[1] if len(sys.argv) > 1 else 'neshizoid'
    s = serial(who)
    print(f'name:   {who}')
    print(f'serial: {s}')
    print(f'self-check: {check(who, s)}')
