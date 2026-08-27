#!/usr/bin/env python3
"""verify.py [crack_me.exe] [PASSWORD ...]

Runs the whole program under Unicorn. This is the first 64 bit PE here, so the
harness had to learn the windows x64 convention: arguments in rcx/rdx/r8/r9 and
32 bytes of shadow space the callee is free to spill into.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

ENTRY = 0x400410


def run(path, guess: bytes):
    emu = Emu(path, base=0)
    st = {'out': []}

    @emu.stub_import('puts')
    def _puts(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 0

    @emu.stub_import('gets_s')
    def _gets(e):
        e.uc.mem_write(e.arg(0), guess + b'\0')
        return e.arg(0)

    @emu.stub_import('__acrt_iob_func')
    def _iob(e):
        return emu.HEAP + 0x800

    @emu.stub_import('__stdio_common_vfprintf')
    def _vfprintf(e):
        return 0

    emu.call(ENTRY)
    return st['out']


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'crack_me.exe')
    want = solve.password(path)
    cands = [a.encode() for a in args if not Path(a).exists()] or [
        want, want + b'X', want[:-1] + b'Z', b'hunter2']
    bad = 0
    for c in cands:
        out = run(path, c)
        verdict = next((l for l in out if 'job' in l or 'clue' in l), '(no verdict)')
        ok = 'job' in verdict
        bad += ok != (c == want)
        print(f'{c.decode("latin1"):16} {verdict}')
    print(f'\npassword: {want.decode()}   ({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
