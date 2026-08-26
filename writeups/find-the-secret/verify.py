#!/usr/bin/env python3
"""verify.py [CrackMe2.exe] [PASSWORD ...]

Calls the dialog handler at 0x4011a2 under Unicorn, lets WriteProcessMemory
actually perform the self-patch, and then lets the patched bytes execute. What
comes back is whatever MessageBoxA is handed, which is the point of the whole
crackme.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

DLGPROC, WM_COMMAND = 0x4011A2, 0x111


def run(path, text: bytes):
    emu = Emu(path, base=0)
    st = {'patch': None, 'msg': []}

    @emu.stub_import('GetDlgItemTextA', argc=4)
    def _get(e):
        e.uc.mem_write(e.arg(2), text + b'\0')
        return len(text)

    @emu.stub_import('WriteProcessMemory', argc=5)
    def _wpm(e):
        data = bytes(e.uc.mem_read(e.arg(2), e.arg(3)))
        st['patch'] = (e.arg(1), data)
        e.uc.mem_write(e.arg(1), data)       # let it rewrite its own code
        return 1

    @emu.stub_import('MessageBoxA', argc=4)
    def _box(e):
        st['msg'].append((e.read_cstr(e.arg(1)).decode('latin1'),
                          e.read_cstr(e.arg(2)).decode('latin1')))
        return 1

    for n in ('SendMessageA', 'LoadIconA', 'EndDialog'):
        emu.stub_import(n, lambda e: 0, argc=4)

    emu.call(DLGPROC, 0x1234, WM_COMMAND, 1, 0)
    return st


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'CrackMe2.exe')
    want = solve.password()
    cands = [a.encode() for a in args if not Path(a).exists()] or [
        want, b'[_Crack_x', b'aaaaaaaaa']
    bad = 0
    for c in cands:
        st = run(path, c)
        code = st['patch'][1].hex(' ') if st['patch'] else '(no patch)'
        ok = bool(st['msg'])
        bad += ok != (c == want)
        print(f'{c.decode("latin1"):11} {code}')
        for text, caption in st['msg']:
            print(f'{"":11} -> {text!r} / {caption!r}')
        if not st['msg']:
            print(f'{"":11} -> nothing, the patched bytes are not a valid call')
    print(f'\npassword: {want.decode()}   ({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
