#!/usr/bin/env python3
"""lincrackme3 keygen.

The key is XXXX-YYYY-WWWW-ZZZZ, 16 digits. main only ever looks at the four
digit sums s1..s4 (one per group), and wants:

    s1 + s2 == 2 * (s3 + s4)
    s2 > s3
    (s1 + s4) even
    5 < s1 <= 24
    s4 odd                      <- and with the line above this forces s1 odd

The individual digits are free, so every solution is really a solution class.

no args prints keys, -c KEY checks one.
"""
import random
import sys

GROUPS = 4
DIGITS = 4


def sums(key):
    d = [int(c) for c in key if c.isdigit()]
    if len(d) != 16:
        return None
    return [sum(d[4 * g:4 * g + 4]) for g in range(GROUPS)]


def check(key):
    s = sums(key)
    if s is None:
        return False
    s1, s2, s3, s4 = s
    return (s1 + s2 == 2 * (s3 + s4)
            and s2 > s3
            and (s1 + s4) % 2 == 0
            and 5 < s1 <= 24
            and s4 % 2 == 1)


def digits_summing_to(total, rnd):
    """Four digits with the given sum, picked at random."""
    while True:
        d = []
        left = total
        for pos in range(DIGITS):
            room = DIGITS - pos - 1
            lo = max(0, left - 9 * room)
            hi = min(9, left)
            if lo > hi:
                break
            pick = rnd.randint(lo, hi)
            d.append(pick)
            left -= pick
        if len(d) == DIGITS and left == 0:
            return d


def solutions():
    """Every (s1, s2, s3, s4) the checker accepts."""
    for s1 in range(7, 25, 2):                 # odd, 5 < s1 <= 24
        for s4 in range(1, 37, 2):             # odd
            for s3 in range(0, 37):
                s2 = 2 * (s3 + s4) - s1
                if 0 <= s2 <= 36 and s2 > s3:
                    yield s1, s2, s3, s4


def keygen(n=10, seed=None):
    rnd = random.Random(seed)
    combos = list(solutions())
    out = []
    for _ in range(n):
        s = rnd.choice(combos)
        cols = [digits_summing_to(t, rnd) for t in s]
        key = '-'.join(''.join(map(str, cols[g])) for g in range(GROUPS))
        out.append((key, s))
    return out


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '-c':
        k = sys.argv[2]
        print(f'{k}  sums={sums(k)}  {"VALID" if check(k) else "rejected"}')
        return
    for key, s in keygen(seed=0):
        assert check(key)
        print(f'{key}   s={s}')


if __name__ == '__main__':
    main()
