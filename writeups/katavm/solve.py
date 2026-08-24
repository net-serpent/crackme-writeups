#!/usr/bin/env python3
"""KataVM Level 1.

The check is virtualized: 15KB of bytecode runs on a little VM whose register
file is a ring of eight 32-bit slots. read() drops four bytes at a time
straight into that ring, eight bytes get mixed, and two of the slots are
compared against constants. That happens twice, so the input is 16 bytes and
the same function has to be inverted on each half.

Nothing here decodes the bytecode. Control flow through the VM never depends on
the input, so every run executes the same 2592 steps; derive.py recovers what
each step does from a handful of traces, and this file walks that straight-line
program backwards, undoing one half-round at a time with z3.

    python3 solve.py            print the answer (uses the recovered constant)
    python3 solve.py --search   redo the whole recovery and inversion
"""
import sys

from z3 import BitVec, BitVecVal, LShR, Or, Solver, sat

ANSWER = b'xNVa2_N07_t3aAlg'

NSLOT = 8
ARITH = ('add', 'sub', 'xor', 'rsub', 'shl', 'shr', 'addr', 'subr', 'xorr')
READS = {'copy': 1, 'add': 1, 'sub': 1, 'xor': 1, 'rsub': 1, 'shl': 1, 'shr': 1,
         'addr': 2, 'subr': 2, 'xorr': 2, 'keep': 0, 'const': 0}
M = 0xFFFFFFFF

# where read() lands, and what the VM compares each half against
HALVES = (
    (301, 1444, ((2, 0xFB987633), (3, 0xA2500488))),
    (1448, 2588, ((2, 0x6CE7082D), (3, 0xC03A492F))),
)
MAX_MODELS = 12


def srcs(r):
    n = READS[r[0]]
    return [r[1]] if n == 1 else ([r[1], r[2]] if n == 2 else [])


def step_apply(rules, s, sym=False):
    """Run one recovered step, over ints or over z3 terms."""
    out = list(s)
    for d, r in enumerate(rules):
        if r is None or r[0] == 'keep':
            continue
        k, a = r[0], r[1] if len(r) > 1 else None
        if k == 'const':
            out[d] = BitVecVal(r[1], 32) if sym else r[1]
        elif k == 'copy':
            out[d] = s[a]
        elif k == 'add':
            out[d] = s[a] + r[2] if sym else (s[a] + r[2]) & M
        elif k == 'sub':
            out[d] = s[a] - r[2] if sym else (s[a] - r[2]) & M
        elif k == 'xor':
            out[d] = s[a] ^ r[2]
        elif k == 'rsub':
            out[d] = r[2] - s[a] if sym else (r[2] - s[a]) & M
        elif k == 'shl':
            out[d] = s[a] << r[2] if sym else (s[a] << r[2]) & M
        elif k == 'shr':
            out[d] = LShR(s[a], r[2]) if sym else s[a] >> r[2]
        elif k == 'addr':
            out[d] = s[a] + s[r[2]] if sym else (s[a] + s[r[2]]) & M
        elif k == 'subr':
            out[d] = s[a] - s[r[2]] if sym else (s[a] - s[r[2]]) & M
        elif k == 'xorr':
            out[d] = s[a] ^ s[r[2]]
    return out


class Half:
    """One 8-byte block: the slice of the program between read and compare."""

    PROBES = (b'ABCDEFGH', b'ZYXWVUTS', b'01234567', b'\x00\x01\x02\x03\x04\x05\x06\x07',
              b'\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8', b'qwertyui')

    def __init__(self, prog, trace, start, last, targets):
        self.prog, self.trace = prog, trace
        self.start, self.last, self.targets = start, last, targets
        self.steps = range(start + 2, last + 1)
        self.bounds = self._bounds()
        self.live = self._liveness()

    def _bounds(self, per=16):
        """Segment boundaries. One half-round is 8 arithmetic ops; inverting two
        at a time gives the solver enough constraints to pin the state down."""
        arith = [s for s in self.steps for r in self.prog[s] if r and r[0] in ARITH]
        return [arith[i] for i in range(0, len(arith), per)] + [self.last + 1]

    def _liveness(self):
        """Backwards liveness, so each boundary carries 3 or 4 slots, not 8."""
        live = {t[0] for t in self.targets}
        out = {self.last + 1: set(live)}
        for step in range(self.last, self.start + 1, -1):
            new, written = set(), set()
            for d, r in enumerate(self.prog[step]):
                if r is None or r[0] == 'keep':
                    if d in live:
                        new.add(d)
                    continue
                written.add(d)
                if d in live:
                    new |= set(srcs(r))
            live = new | (live - written)
            out[step] = set(live)
        return out

    def reference(self, inp8):
        s = list(self.trace[self.start][2])
        s[0] = int.from_bytes(inp8[0:4], 'little')
        s[1] = int.from_bytes(inp8[4:8], 'little')
        st = {self.start + 2: list(s)}
        for step in self.steps:
            s = step_apply(self.prog[step], s)
            st[step + 1] = list(s)
        return st

    def independent(self):
        runs = [self.reference(p) for p in self.PROBES]
        return {st: {i for i in range(NSLOT) if len({r[st][i] for r in runs}) == 1}
                for st in runs[0]}

    def forward(self, state, lo):
        cur = list(state)
        for step in range(lo, self.last + 1):
            cur = step_apply(self.prog[step], cur)
        return cur

    def _models(self, ref, indep, lo, hi, known):
        unknown = sorted(self.live[lo] - indep[lo])
        sym = [BitVec(f'u{i}', 32) if i in unknown else BitVecVal(ref[lo][i], 32)
               for i in range(NSLOT)]
        cur = sym
        for step in range(lo, hi):
            cur = step_apply(self.prog[step], cur, sym=True)
        s = Solver()
        for slot, val in known.items():
            s.add(cur[slot] == val)
        out = []
        while len(out) < MAX_MODELS and s.check() == sat:
            m = s.model()
            vals = [m[sym[i]].as_long() if i in unknown and m[sym[i]] is not None
                    else ref[lo][i] for i in range(NSLOT)]
            out.append(vals)
            s.add(Or([sym[i] != vals[i] for i in unknown]))
        return out

    def solve(self):
        """Walk the half-rounds backwards; a half-round can have several
        preimages, so keep the alternatives and backtrack when one dies."""
        ref = self.reference(b'ABCDEFGH')
        indep = self.independent()
        stack = [(len(self.bounds) - 2, {s: v for s, v in self.targets})]
        choices = {}
        while stack:
            k, known = stack[-1]
            if k < 0:
                return known
            lo, hi = self.bounds[k], self.bounds[k + 1]
            if k not in choices:
                choices[k] = self._models(ref, indep, lo, hi, known)
            while choices[k]:
                cand = choices[k].pop(0)
                got = self.forward(cand, lo)
                if all(got[slot] == val for slot, val in self.targets):
                    stack.append((k - 1, {i: cand[i] for i in self.live[lo]}))
                    break
            else:
                choices.pop(k, None)
                stack.pop()
        raise RuntimeError('no preimage')


def search(verbose=True):
    from derive import derive, traces
    tr = traces(2)
    prog, unexplained = derive(tr)
    assert {s for s, _ in unexplained} == {301, 302, 1448, 1449}, unexplained
    out = bytearray()
    for start, last, targets in HALVES:
        h = Half(prog, tr[0][1], start, last, targets)
        known = h.solve()
        out += known[0].to_bytes(4, 'little') + known[1].to_bytes(4, 'little')
        if verbose:
            print(f'  half at step {start}: {bytes(out[-8:]).decode("latin1")}',
                  file=sys.stderr)
    return bytes(out)


if __name__ == '__main__':
    print((search() if '--search' in sys.argv else ANSWER).decode('latin1'))
