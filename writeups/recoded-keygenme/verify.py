#!/usr/bin/env python3
"""verify.py [KeygenMe.exe] [NAME ...]

Calls the dialog's check routine at 0x4010ef directly, under Unicorn, with
GetDlgItemTextA handing it a name and a serial and MessageBoxA capturing the
verdict. The dialog itself never runs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                             # noqa: E402

CHECK = 0x4010EF
ID_SERIAL, ID_NAME = 0x3EA, 0x3E9


def run(path, name: str, ser: str):
    emu = Emu(path, base=0)
    st = {'verdict': None}

    @emu.stub_import('GetDlgItemTextA', argc=4)
    def _get(e):
        _hdlg, ident, buf, cap = e.arg(0), e.arg(1), e.arg(2), e.arg(3)
        text = (ser if ident == ID_SERIAL else name).encode()[:cap - 1]
        e.uc.mem_write(buf, text + b'\0')
        return len(text)

    @emu.stub_import('MessageBoxA', argc=4)
    def _msg(e):
        st['verdict'] = e.read_cstr(e.arg(1)).decode('latin1')
        return 1

    for extra in ('SetDlgItemTextA', 'EndDialog', 'SetTimer'):
        emu.stub_import(extra, lambda e: 0, argc=4)

    emu.call(CHECK, 0x1234)
    return st['verdict'] or '(no verdict)'


def main():
    args = sys.argv[1:]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'KeygenMe.exe')
    names = [a for a in args if not Path(a).exists()] or ['neshizoid', 'promix17', 'abcd']
    bad = 0
    for who in names:
        good = solve.serial(who)
        v = run(path, who, good)
        ok = 'Nice work' in v
        bad += not ok
        print(f'{who:12} {good}  {v}')
    wrong = solve.serial('neshizoid')[:-1] + ('0' if solve.serial('neshizoid')[-1] != '0' else '1')
    v = run(path, 'neshizoid', wrong)
    bad += 'Nice work' in v
    print(f'{"neshizoid":12} {wrong}  {v}   (one digit off)')
    print(f'\n{len(names) + 1 - bad}/{len(names) + 1} as expected')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
