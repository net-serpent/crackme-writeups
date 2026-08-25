#!/usr/bin/env python3
"""verify.py [LTFFT.exe] [PASSWORD ...]

Runs the crackme's main under Unicorn. MinGW console PE: printf, scanf, strcmp
and system come from msvcrt, so they get python stubs; createGoodBoy and the
comparison run as compiled.

With no arguments it also checks goal two by patching a name into a copy and
reading the banner back out.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

MAIN = 0x401290
SYM = {'crt_init': 0x401470, 'strcmp': 0x4018D0, 'scanf': 0x4018E0,
       'printf': 0x4018F0, 'system': 0x4018C0}


def run(path, candidate: bytes):
    emu = Emu(path, base=0)
    st = {'out': []}

    @emu.stub(SYM['crt_init'])
    def _crt(e):
        return 0

    @emu.stub(SYM['printf'])
    def _printf(e):
        fmt = e.read_cstr(e.arg(0)).decode('latin1')
        if '%s' in fmt:
            fmt = fmt.replace('%s', e.read_cstr(e.arg(1)).decode('latin1'), 1)
        st['out'].append(fmt)
        return len(fmt)

    @emu.stub(SYM['scanf'])
    def _scanf(e):
        e.uc.mem_write(e.arg(1), candidate + b'\0')
        return 1

    @emu.stub(SYM['strcmp'])
    def _strcmp(e):
        a, b = e.read_cstr(e.arg(0)), e.read_cstr(e.arg(1))
        return 0 if a == b else (1 if a > b else 0xFFFFFFFF)

    @emu.stub(SYM['system'])
    def _system(e):
        return 0

    emu.call(MAIN)
    return ''.join(st['out'])


def verdict(text):
    return next((l for l in text.splitlines() if 'Well done' in l or 'Bad...' in l),
                '(no verdict)')


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'LTFFT.exe')
    want = solve.password()
    cands = [a for a in args if not Path(a).exists()] or [want, '[DEIBIZ)', 'password']
    bad = 0
    for c in cands:
        out = run(path, c.encode())
        ok = 'Well done' in out
        bad += ok != (c == want)
        print(f'{c:12} {verdict(out)}')

    with tempfile.TemporaryDirectory() as td:
        patched = str(Path(td) / 'LTFFT-patched.exe')
        solve.patch_name(path, patched, 'neshizoid')
        line = next((l for l in run(patched, want.encode()).splitlines()
                     if 'Cracked By' in l), '')
        ok = 'neshizoid' in line
        bad += not ok
        print(f'\ngoal two: {line.strip()}  ({"ok" if ok else "WRONG"})')
    print(f'password: {want}   ({"all as expected" if not bad else "MISMATCH"})')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
