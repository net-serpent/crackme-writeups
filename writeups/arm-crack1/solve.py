#!/usr/bin/env python3
"""arm_crack1 by blankwall. ARM Thumb, and the flag is sitting in .rodata
under a shift of 20.

main copies the 12 bytes at 0x8a70 into a buffer, pushes each one through
fcn.0000877c, and compares the result with what you typed. That function is 138
bytes of arithmetic where exactly one line survives to the return:

    if (a > 10) c = a;          /* a is the byte, so always taken   */
    ...                          /* six lines writing dead locals    */
    return c + 0x14;

Everything else lands in stack slots nothing ever reads again.

    python3 solve.py            the flag
    python3 solve.py -c WORD    check a candidate
"""
import sys

CIPHER_VA = 0x8A70
SHIFT = 0x14
LENGTH = 12


def cipher(path='Arm_crackme/arm_crack1') -> bytes:
    from elftools.elf.elffile import ELFFile
    with open(path, 'rb') as f:
        for seg in ELFFile(f).iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                lo, size = seg['p_vaddr'], seg['p_filesz']
                if lo <= CIPHER_VA < lo + size:
                    off = CIPHER_VA - lo
                    return seg.data()[off:off + LENGTH]
    raise KeyError(hex(CIPHER_VA))


def flag(path='Arm_crackme/arm_crack1') -> bytes:
    return bytes((b + SHIFT) & 0xFF for b in cipher(path))


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '-c':
        want = flag().decode()
        got = sys.argv[2]
        print(f'{got!r} -> {"VALID" if got == want else "rejected"}')
        return
    raw = cipher()
    print(f'cipher: {raw!r}  {raw.hex(" ")}')
    print(f'+0x14 : {flag().decode()}')


if __name__ == '__main__':
    main()
