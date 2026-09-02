#!/usr/bin/env python3
"""ray33ee's "x or and add". Keygen: for any name, print the one password that
passes.

The check is symmetric enough to invert by hand. main reduces the name to a
bucket

    H = (sum of name bytes) mod 400

and pulls three bytes out of a table indexed by that bucket:

    E0, E1, E2 = TABLE[3H], TABLE[3H+1], TABLE[3H+2]

Then, for each position i of a 12-char password, it wants

    ((pw[i] ^ E0) + E1) ^ E2 == REF[i]        REF = "Cr4ckM35D0t1"

E0/E1/E2 are the same for every position, so each password byte is independent
and the whole thing runs backwards:

    pw[i] = (((REF[i] ^ E2) - E1) ^ E0) & 0xff

The table lives in the binary; TABLE below is lifted straight out of .rdata at
0x140013040 (only the low byte of each dword is ever used). Because the reduction
is mod 400, there are just 400 possible passwords total, one per bucket, and every
name lands in some bucket, so any name has a valid password. That is the whole
keyspace: 400 distinct keys, names are a many-to-one label on top.
"""
import sys
from pathlib import Path

REF = b'Cr4ckM35D0t1'
MOD = 400

# low byte of each dword at 0x140013040, 3 per bucket, buckets 0..399
TABLE = None  # filled from table.txt next to this file


def _load_table():
    global TABLE
    if TABLE is None:
        raw = (Path(__file__).with_name('table.txt')).read_text().split()
        TABLE = [int(x, 16) & 0xFF for x in raw]
    return TABLE


def bucket(name: str) -> int:
    return sum(name.encode()) % MOD


def consts(name: str):
    t = _load_table()
    h = bucket(name)
    return t[3 * h], t[3 * h + 1], t[3 * h + 2]


def password(name: str):
    """The password for a name, or None if the bucket has no byte solution.

    A bucket fails only if REF[i]^E2 < E1 for some i (the intermediate would have
    to be negative). In this particular table every bucket happens to work and
    every one of them is printable, so None never actually comes up, but the
    guard keeps the keygen honest about the arithmetic.
    """
    e0, e1, e2 = consts(name)
    out = bytearray()
    for r in REF:
        v = (r ^ e2) - e1
        if v < 0:
            return None
        out.append((v ^ e0) & 0xFF)
    return bytes(out)


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'adjacent'
    pw = password(name)
    if pw is None:
        print(f'{name!r}: no password (bucket {bucket(name)} has no byte solution)')
        return 1
    print(f'name:     {name}')
    print(f'password: {pw.decode("latin1")}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
