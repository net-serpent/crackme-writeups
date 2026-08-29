#!/usr/bin/env python3
"""verify.py [SimpleKeyGen] [SERIAL ...]

Calls checkSerial at 0x1197 directly under Unicorn, stubbing only strlen.
A good serial returns 0.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

CHECK, STRLEN = 0x1197, 0x1040


def run(path, serial: bytes):
    emu = Emu(path, base=0)

    @emu.stub(STRLEN)
    def _strlen(e):
        return len(e.read_cstr(e.arg(0)))

    buf = emu.alloc(serial + b'\0')
    rv = emu.call(CHECK, buf)
    if isinstance(rv, str):
        return rv
    return 'Good Serial' if (rv & 0xFFFFFFFF) == 0 else 'Bad Serial'


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'SimpleKeyGen')
    good = solve.serial()
    cands = [a for a in args if not Path(a).exists()] or [good, good[:-1] + 'Z', 'short', 'A' * 16]
    bad = 0
    for c in cands:
        v = run(path, c.encode())
        ok = v == 'Good Serial'
        bad += ok != solve.check(c)
        print(f'{c:18} {v}')
    print(f'\nserial: {good}   ({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
