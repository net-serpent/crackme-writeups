#!/usr/bin/env python3
"""tiny_crackme by yanisto.

769 bytes of hand written asm that decrypts 676 bytes of itself and then reads
exactly 4 bytes of password. The check at 0x2000b1 is

    xor ebx, dword [0x200296]      ; ebx == the 4 bytes you typed?
    jne  wrong

where ebx comes out of the routine at 0x2002c9. Probing that routine one input
byte at a time shows each input byte drives exactly one byte of ebx, through
the permutation

    input[0] -> ebx[2]    input[1] -> ebx[3]
    input[2] -> ebx[0]    input[3] -> ebx[1]

so `ebx == input` splits into two independent 2-cycles and the whole thing
falls to 2 * 256 probes. There is no single answer: 256 four-byte strings pass.
The author clearly meant this one.

The transform only exists after the binary decrypts itself, so the search
lives in verify.py where the emulator is. This file just carries the result.
"""
PASSWORD = b'b00m'

# every accepted value is (a, b, c, d) with c = F0(a), a = F2(c), d = F1(b),
# b = F3(d); these are the printable ones, recovered by verify.py --search
PRINTABLE = [
    b'b(0e', b'b*0g', b'b,0a', b'b.0c', b'b00m', b'b20o', b'b40i', b'b60k',
    b'f(4e', b'f*4g', b'f,4a', b'f.4c', b'f04m', b'f24o', b'f44i', b'f64k',
    b'r(@e', b'r*@g', b'r,@a', b'r.@c', b'r0@m', b'r2@o', b'r4@i', b'r6@k',
    b'v(De', b'v*Dg', b'v,Da', b'v.Dc', b'v0Dm', b'v2Do', b'v4Di', b'v6Dk',
]

if __name__ == '__main__':
    print(f'password: {PASSWORD.decode()}')
    print(f'{len(PRINTABLE)} other printable ones also work, e.g. '
          + ', '.join(p.decode() for p in PRINTABLE[:6]))
