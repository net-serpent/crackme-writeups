#!/usr/bin/env python3
"""verify.py [xorcist] [PASSWORD ...]

Calls validate at 0x1349 directly under Unicorn - strcpy/decrypt/strcmp run as
compiled, so the encrypted blob and the 0xA9 key come straight from the binary.
Returns 1 for the right password.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

VALIDATE, STRCPY, STRCMP = 0x1349, 0x1040, 0x10C0


def run(path, guess: bytes):
    emu = Emu(path, base=0)

    @emu.stub(STRCPY)
    def _strcpy(e):
        s = e.read_cstr(e.arg(1))
        e.uc.mem_write(e.arg(0), s + b'\0')
        return e.arg(0)

    @emu.stub(STRCMP)
    def _strcmp(e):
        a, b = e.read_cstr(e.arg(0)), e.read_cstr(e.arg(1))
        return 0 if a == b else 1

    buf = emu.alloc(guess + b'\0')
    rv = emu.call(VALIDATE, buf)
    return isinstance(rv, int) and (rv & 0xFF) == 1


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'xorcist')
    want = solve.password(path)
    cands = [a for a in args if not Path(a).exists()] or [want, want + 'x', 'password']
    bad = 0
    for c in cands:
        ok = run(path, c.encode())
        bad += ok != (c == want)
        print(f'{c:18} {"accepted" if ok else "rejected"}')
    print(f'\npassword: {want}   ({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
