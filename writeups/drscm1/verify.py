#!/usr/bin/env python3
"""verify.py ./drscm1/drscm1 [NAME SERIAL]

Runs the real main() under Unicorn with libc stubbed, so the binary does its
own XTEA decryption of the payload and calls it for real. Prints whichever of
the two callbacks fires.

Also decrypts the payload with solve.py and diffs it against what the binary
put in memory, and checks a patched binary from solve.patch() accepts anything.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

MAIN = 0x8048627
PLT = {
    'puts': 0x804839C, 'malloc': 0x80483AC, 'mprotect': 0x80483BC,
    'fgets': 0x80483CC, 'strndup': 0x80483EC, 'printf': 0x80483FC,
    'exit': 0x804840C, 'atoi': 0x804841C, 'free': 0x804842C,
}
PAYLOAD_PTR = 0x8049B8C


def run(path, name: str, serial: str):
    emu = Emu(path, base=0)
    st = {'lines': [f'{name}\n', f'{serial}\n'], 'out': [], 'payload': None}

    @emu.stub(PLT['malloc'])
    def _malloc(e):
        return e.alloc(bytes(e.arg(0) + 16))

    @emu.stub(PLT['free'])
    def _free(e):
        return 0

    @emu.stub(PLT['mprotect'])
    def _mprotect(e):
        return 0

    @emu.stub(PLT['puts'])
    def _puts(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 1

    @emu.stub(PLT['printf'])
    def _printf(e):
        fmt = e.read_cstr(e.arg(0)).decode('latin1')
        if '%s' in fmt:
            fmt = fmt.replace('%s', e.read_cstr(e.arg(1)).decode('latin1'), 1)
        st['out'].append(fmt)
        return 1

    @emu.stub(PLT['fgets'])
    def _fgets(e):
        line = (st['lines'].pop(0) if st['lines'] else '\n').encode()
        e.uc.mem_write(e.arg(0), line + b'\0')
        return e.arg(0)

    @emu.stub(PLT['strndup'])
    def _strndup(e):
        return e.alloc(e.read_cstr(e.arg(0))[:e.arg(1)] + b'\0')

    @emu.stub(PLT['atoi'])
    def _atoi(e):
        txt = e.read_cstr(e.arg(0)).strip()
        try:
            return int(txt) & 0xFFFFFFFF
        except ValueError:
            return 0

    @emu.stub(PLT['exit'])
    def _exit(e):
        e.uc.emu_stop()

    st['rv'] = emu.call(MAIN, 0, 0, 0)
    ptr = emu.read_word(PAYLOAD_PTR)
    if ptr:
        st['payload'] = bytes(emu.uc.mem_read(ptr, 56))
    return ''.join(st['out']), st['payload'], st['rv']


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]

    if len(sys.argv) > 3:
        out, _, rv = run(path, sys.argv[2], sys.argv[3])
        print(out.strip())
        return 0

    bad = 0
    print('payload decrypted by the binary vs by solve.py:')
    _, payload, rv = run(path, 'test', '123')
    mine = solve.plaintext(path)
    print(f'  rv={rv}')
    print(f'  {"match" if payload == mine else "MISMATCH"}   {mine.hex(" ")[:47]}...')
    bad += payload != mine

    print('\nname / serial pairs:')
    for name in ('Dr.Spliff', 'neshizoid', 'a'):
        s = solve.serial(name)
        for cand, want in ((s, True), (s + 1, False)):
            out, _, _rv = run(path, name, str(cand))
            got = 'Congrats' in out
            bad += got != want
            print(f'  {name:10} {cand:6} -> {"Congrats" if got else "Sorry"} '
                  f'({"ok" if got == want else "WRONG"})')

    with tempfile.TemporaryDirectory() as td:
        patched = str(Path(td) / 'drscm1-patched')
        solve.patch(path, patched)
        out, _, _rv = run(patched, 'whoever', '12345')
        ok = 'Congrats' in out
        bad += not ok
        print(f'\npatched binary, junk serial -> {"Congrats" if ok else "Sorry"} '
              f'({"ok" if ok else "WRONG"})')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
