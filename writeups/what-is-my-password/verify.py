#!/usr/bin/env python3
"""verify.py [cme6.exe] [PASSWORD ...]

Runs the crackme's own main under Unicorn. This is a PE rather than an ELF,
but the CRT is linked statically, so the check calls nothing from kernel32:
stubbing the four internal helpers (print, read a line, fail, pause) is enough
and no import table has to be resolved at all.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

MAIN = 0x401000
PRINT, READLINE, FAIL, PAUSE, EXIT = 0x40121A, 0x4011D0, 0x4011B0, 0x405016, 0x401278


def run(path, candidate: bytes):
    emu = Emu(path, base=0)
    st = {'out': [], 'failed': False}

    @emu.stub(PRINT)
    def _print(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 0

    @emu.stub(READLINE)
    def _readline(e):
        e.uc.mem_write(e.arg(0), candidate + b'\0')
        return e.arg(0)

    @emu.stub(FAIL)
    def _fail(e):
        st['failed'] = True
        e.uc.emu_stop()

    @emu.stub(PAUSE)
    def _pause(e):
        return 0

    @emu.stub(EXIT)
    def _exit(e):
        e.uc.emu_stop()

    emu.call(MAIN)
    text = ''.join(st['out'])
    if st['failed']:
        return 'You have failed!'
    return next((l for l in text.splitlines() if 'Congrats' in l or 'failed' in l),
                '(no verdict)')


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'cme6.exe')
    want = solve.password()
    cands = [a for a in args if not Path(a).exists()] or [want, '95718t00x', 'password1']
    bad = 0
    for c in cands:
        verdict = run(path, c.encode())
        ok = 'Congrats' in verdict
        bad += ok != (c == want)
        print(f'{c:12} {verdict}')
    print(f'\npassword: {want}   ({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
