#!/usr/bin/env python3
"""learn_the_first_few_tricks #1 by deibiz_xxl.

Two goals, and the instructions spell them out: find the password without
patching, then patch the name the program prints.

The password comes from createGoodBoy at 0x401357, which is eight lines long:

    for (i = 0; i <= 7; i++)
        buf[i] = "ZCDHAHY\\"[i] + 1;

and the result is strcmp'd against what you typed. Adding one to each byte of
that string spells the author's own handle.

    python3 solve.py                    the password
    python3 solve.py --patch IN OUT NAME  goal two: put NAME in the banner
"""
import sys

MAGIC_VA, NAME_VA, NAME_LEN = 0x402000, 0x402009, 12
MAGIC = b'ZCDHAHY\\'


def password() -> str:
    return ''.join(chr((c + 1) & 0xFF) for c in MAGIC)


def _file_offset(raw, va):
    import struct
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    nsect, = struct.unpack_from('<H', raw, pe + 6)
    optsize, = struct.unpack_from('<H', raw, pe + 20)
    base, = struct.unpack_from('<I', raw, pe + 52)
    off = pe + 24 + optsize
    for i in range(nsect):
        e = off + i * 40
        vaddr, = struct.unpack_from('<I', raw, e + 12)
        vsize, = struct.unpack_from('<I', raw, e + 8)
        rawptr, = struct.unpack_from('<I', raw, e + 20)
        if base + vaddr <= va < base + vaddr + vsize:
            return rawptr + (va - base - vaddr)
    raise KeyError(hex(va))


def patch_name(src, dst, name: str):
    """Goal two: the banner prints a 12 byte placeholder, so overwrite it."""
    raw = bytearray(open(src, 'rb').read())
    off = _file_offset(raw, NAME_VA)
    assert raw[off:off + NAME_LEN] == b'X' * NAME_LEN, 'placeholder not found'
    text = name.encode()[:NAME_LEN]
    raw[off:off + NAME_LEN] = text + b'\0' * (NAME_LEN - len(text))
    open(dst, 'wb').write(bytes(raw))
    return off


def main():
    if '--patch' in sys.argv:
        i = sys.argv.index('--patch')
        off = patch_name(sys.argv[i + 1], sys.argv[i + 2], sys.argv[i + 3])
        print(f'name written at file offset {off:#x} -> {sys.argv[i + 2]}')
    else:
        print(password())


if __name__ == '__main__':
    main()
