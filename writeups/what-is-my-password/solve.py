#!/usr/bin/env python3
"""what_is_my_password by br0ken.

The check is a system of linear equations over the first five characters plus
four standalone conditions on the tail, all compiled into lea/sub chains:

    3a - b + 2c - d + 3e = 347
    6a - 2b - c + 3d - 4e = 104
     a + 3b - 3c + 7d + e = 450
    2a + b + 3c + 3d - 7e = 87
     a + b + c + d + e = 270          (a..e are password[0..4])

    password[6] ^ 0x6f == 0x5f        -> '0'
    password[7] == password[6]        -> '0'
    password[8] - password[5] == 3
    password[8] + password[5] == 235  -> 'w' and 't'

and the length has to be 9. Five equations for five unknowns, so there is
exactly one answer, and the crackme prints its own MD5 so you can check it
without running anything.
"""
from fractions import Fraction

MD5 = '7eeeec6420a2a99b123f66b5c5231547'
SYSTEM = ([[3, -1, 2, -1, 3], [6, -2, -1, 3, -4], [1, 3, -3, 7, 1],
           [2, 1, 3, 3, -7], [1, 1, 1, 1, 1]],
          [347, 104, 450, 87, 270])


def head() -> str:
    """Gauss over the five linear constraints."""
    A, b = SYSTEM
    n = len(b)
    m = [[Fraction(A[i][j]) for j in range(n)] + [Fraction(b[i])] for i in range(n)]
    for c in range(n):
        p = next(r for r in range(c, n) if m[r][c])
        m[c], m[p] = m[p], m[c]
        m[c] = [x / m[c][c] for x in m[c]]
        for r in range(n):
            if r != c and m[r][c]:
                f = m[r][c]
                m[r] = [x - f * y for x, y in zip(m[r], m[c])]
    return ''.join(chr(int(m[i][n])) for i in range(n))


def tail() -> str:
    p6 = 0x5F ^ 0x6F
    p7 = p6
    p8, p5 = (235 + 3) // 2, (235 - 3) // 2
    return chr(p5) + chr(p6) + chr(p7) + chr(p8)


def password() -> str:
    return head() + tail()


if __name__ == '__main__':
    import hashlib
    pw = password()
    print(f'password: {pw}')
    print(f'md5     : {hashlib.md5(pw.encode()).hexdigest()}')
    print(f'expected: {MD5}   {"match" if hashlib.md5(pw.encode()).hexdigest() == MD5 else "MISMATCH"}')
