#!/usr/bin/env python3
"""verify.py [name ...]

Runs the crackme's real main (fcn.1400017b4) under Unicorn and feeds it a
name/password pair through stubbed scanf, then reads back what it tried to print.
"yes" means the pair passed the actual check, not my model of it.

Stubbed, all thin wrappers with nothing to decide:
  0x1400019a7  startup init  -> noop
  0x140001634  printf(fmt..) -> capture the format string
  0x1400015e0  scanf(fmt,buf)-> drop the next queued input into buf
  strlen       (import)      -> len to the NUL
Everything that matters, the name hash, the table lookup, and the xor/add/xor
comparison, runs as compiled.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

MAIN, INIT, PRINTF, SCANF = 0x1400017B4, 0x1400019A7, 0x140001634, 0x1400015E0


def run(path, name: str, pw: str) -> str:
    emu = Emu(path, base=0)
    printed = []
    feed = [name.encode(), pw.encode()]

    @emu.stub(INIT)
    def _init(e):
        return 0

    @emu.stub_import('strlen', argc=1)
    def _strlen(e):
        return len(e.read_cstr(e.arg(0)))

    @emu.stub(PRINTF)
    def _printf(e):
        s = e.read_cstr(e.arg(0)).decode('latin1')
        printed.append(s)
        return len(s)

    @emu.stub(SCANF)
    def _scanf(e):
        data = feed.pop(0) if feed else b''
        e.uc.mem_write(e.arg(1), data + b'\0')       # rdx is the destination
        return 1

    rv = emu.call(MAIN, 0)
    if isinstance(rv, str):
        return f'<abort: {rv}>'
    return ''.join(printed)


def main():
    path = str(Path(__file__).with_name('xor_crackme.exe'))
    names = sys.argv[1:] or ['adjacent', 'ray33ee', 'amorous', 'Claude', 'net-serpent']
    bad = 0
    for name in names:
        pw = solve.password(name).decode('latin1')
        out = run(path, name, pw).strip()
        ok = out.endswith('yes')
        bad += not ok
        print(f'name={name!r:14} pw={pw!r:14} -> {out!r}  {"OK" if ok else "FAIL"}')

    wrong = run(path, names[0], 'wrongpass123').strip()
    neg_ok = wrong.endswith('no')
    print(f'\nnegative control (bad password)  -> {wrong!r}  {"OK" if neg_ok else "FAIL"}')
    return 1 if bad or not neg_ok else 0


if __name__ == '__main__':
    raise SystemExit(main())
