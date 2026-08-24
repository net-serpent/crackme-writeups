#!/usr/bin/env python3
"""Recover the VM's straight-line program without decoding its bytecode.

Control flow through the VM does not depend on the input, so every run executes
the same 2592 steps. Trace several inputs, and for each step look for one rule
that explains every changed slot in *all* traces at once. What comes out is the
whole computation as a list of assignments over the 8 slot ring.
"""
import random
import sys

from vmtrace import full_trace

M = 0xFFFFFFFF
SLOTS = 8


def traces(n=6, seed=1):
    rnd = random.Random(seed)
    out = []
    for _ in range(n):
        s = bytes(rnd.randrange(0x21, 0x7f) for _ in range(16))
        out.append((s, full_trace(s + b'\n')))
    return out


def rules_for(step, tr, dst):
    """Every rule that explains slot dst at this step across all traces."""
    befores = [t[step][2] for _, t in tr]
    afters = [t[step + 1][2] for _, t in tr]
    want = [a[dst] for a in afters]
    found = []

    if all(b[dst] == w for b, w in zip(befores, want)):
        return [('keep', dst)]
    if len(set(want)) == 1:
        found.append(('const', want[0]))
    for s in range(SLOTS):
        if all(b[s] == w for b, w in zip(befores, want)):
            found.append(('copy', s))
    for s in range(SLOTS):
        for op, f in (('add', lambda x, c: (x + c) & M), ('sub', lambda x, c: (x - c) & M),
                      ('xor', lambda x, c: x ^ c), ('rsub', lambda c, x: (c - x) & M)):
            c = (want[0] - befores[0][s]) & M if op == 'add' else \
                (befores[0][s] - want[0]) & M if op == 'sub' else \
                (want[0] ^ befores[0][s]) if op == 'xor' else \
                (want[0] + befores[0][s]) & M
            ok = all((f(b[s], c) if op != 'rsub' else f(c, b[s])) == w
                     for b, w in zip(befores, want))
            if ok:
                found.append((op, s, c))
        for k in range(1, 32):
            if all(((b[s] << k) & M) == w for b, w in zip(befores, want)):
                found.append(('shl', s, k))
            if all((b[s] >> k) == w for b, w in zip(befores, want)):
                found.append(('shr', s, k))
        for t in range(SLOTS):
            for op, f in (('addr', lambda x, y: (x + y) & M),
                          ('subr', lambda x, y: (x - y) & M),
                          ('xorr', lambda x, y: x ^ y)):
                if all(f(b[s], b[t]) == w for b, w in zip(befores, want)):
                    found.append((op, s, t))
    return found


def derive(tr):
    n = len(tr[0][1])
    prog = []
    unexplained = []
    for step in range(n - 1):
        asg = []
        for d in range(SLOTS):
            r = rules_for(step, tr, d)
            if not r:
                unexplained.append((step, d))
                asg.append(None)
            else:
                asg.append(r[0])
        prog.append(asg)
    return prog, unexplained


if __name__ == '__main__':
    tr = traces(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
    print(f'{len(tr)} трасс по {len(tr[0][1])} шагов')
    prog, bad = derive(tr)
    print(f'необъяснённых присваиваний: {len(bad)}')
    if bad:
        print('  первые:', bad[:10])
