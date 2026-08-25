#!/usr/bin/env python3
"""verify.py ./1337ARM.bin [ARG ...]

Calls the real main(argc, argv) under Unicorn in ARM mode with argv built in
emulated memory, and prints what it returns. 1337 means accepted.

Only xmalloc and memset are stubbed; everything main does itself runs as
compiled.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

MAIN, XMALLOC, MEMSET = 0x8290, 0x8248, 0x11FE0


def run(path, arg: str):
    emu = Emu(path, base=0, thumb=False)                # this one is plain ARM

    @emu.stub(XMALLOC)
    def _xmalloc(e):
        return e.alloc(bytes(e.arg(0) + 16))

    @emu.stub(MEMSET)
    def _memset(e):
        dst, c, n = e.arg(0), e.arg(1) & 0xFF, e.arg(2)
        if n:
            e.uc.mem_write(dst, bytes([c]) * n)
        return dst

    argv0 = emu.alloc(b'./1337ARM.bin\0')
    argv1 = emu.alloc(arg.encode() + b'\0')
    argv = emu.alloc(b''.join(x.to_bytes(4, 'little') for x in (argv0, argv1, 0)))
    rv = emu.call(MAIN, 2, argv)
    if isinstance(rv, str):
        return rv
    rv &= 0xFFFFFFFF
    return rv - (1 << 32) if rv & 0x80000000 else rv


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    pw = solve.password()
    args = sys.argv[2:] or [pw, pw[:5], pw + 'x', 'ABCE', 'hello']
    bad = 0
    for a in args:
        rv = run(path, a)
        ok = rv == solve.EXIT_OK
        bad += ok != solve.accepted(a)
        print(f'{a!r:36} exit={rv:<6} {"accepted" if ok else "rejected"}')
    print(f'\npassword: {pw!r}   ({len(args) - bad}/{len(args)} match solve.accepted)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
