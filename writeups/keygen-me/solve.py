#!/usr/bin/env python3
"""Keygen-Me by OTC.

The download is a UPX-packed static ELF. Unpack it and the entry point is a
dropper: it decrypts a second ELF held at 0x4020, writes it to an anonymous
memfd_create fd, and fexecve's it. The decryption is

    srand(0x32); for i: plain[i] = enc[i] ^ (rand() & 0xff)

with glibc's own rand(), reimplemented below.

The inner ELF is the real crackme (OpenSSL SHA256, C++). It asks two questions:

    name  -> base64(name) must equal "U3BlZWQ="  ->  name = "Speed"
    topic -> must equal  hex(SHA256( xor42(hex(MD5(name))) ))

where xor42 is a byte-wise xor with 0x42 (fcn.2549). Both are computable, so
the whole flag is:

    Cybersphere{Speed_<topic>}

    python3 solve.py             print the flag (and re-derive the inner ELF)
"""
import hashlib
import sys
from pathlib import Path

BLOB_VA, BLOB_LEN, SEED = 0x4020, 0x58E8, 0x32
NAME = 'Speed'                                   # base64 -> U3BlZWQ=
XOR_KEY = 0x42


class GlibcRand:
    """glibc random() TYPE_3 additive feedback, the default rand()."""

    def __init__(self, seed):
        r = [seed & 0xFFFFFFFF]
        for i in range(1, 31):
            hi, lo = divmod(r[i - 1], 127773)
            w = 16807 * lo - 2836 * hi
            r.append(w + 2147483647 if w < 0 else w)
        for i in range(31, 34):
            r.append(r[i - 31])
        for i in range(34, 344):
            r.append((r[i - 31] + r[i - 3]) & 0xFFFFFFFF)
        self.r, self.i = r, 344

    def next(self):
        self.r.append((self.r[self.i - 31] + self.r[self.i - 3]) & 0xFFFFFFFF)
        self.i += 1
        return (self.r[self.i - 1] >> 1) & 0x7FFFFFFF


def _unpacked(path):
    """UPX -d gives the dropper; parse it and pull the encrypted blob."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
    from ucload import parse_image
    for base, data in parse_image(path)['chunks']:
        if base <= BLOB_VA < base + len(data):
            off = BLOB_VA - base
            return data[off:off + BLOB_LEN]
    raise KeyError


def inner_elf(unpacked='task.unpacked') -> bytes:
    blob = _unpacked(unpacked)
    g = GlibcRand(SEED)
    return bytes(b ^ (g.next() & 0xFF) for b in blob)


def topic(name=NAME) -> str:
    md5hex = hashlib.md5(name.encode()).hexdigest()
    xored = bytes(b ^ XOR_KEY for b in md5hex.encode())
    return hashlib.sha256(xored).hexdigest()


def flag(name=NAME) -> str:
    return f'Cybersphere{{{name}_{topic(name)}}}'


if __name__ == '__main__':
    elf = inner_elf(sys.argv[1] if len(sys.argv) > 1 else 'task.unpacked')
    print(f'inner ELF: {elf[:4]!r}  valid={elf[:4] == bytes.fromhex("7f454c46")}  {len(elf)} bytes')
    print(f'name:  {NAME}')
    print(f'flag:  {flag()}')
