#!/usr/bin/env python3
"""verify.py ./lincrackme3-64 [KEY ...]

Runs the binary's real main() under Unicorn with libc stubbed out, feeding
each key through getchar() and reporting whatever it prints. ptrace() returns
0 so the anti-debug is satisfied honestly rather than patched out.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

MAIN = 0x4008A7
PLT = {
    'printf': 0x400628, 'close': 0x400638, 'puts': 0x400648, 'exit': 0x400658,
    'putchar': 0x400668, 'strncmp': 0x400678, 'ptrace': 0x400698,
    'getchar': 0x4006A8, 'stack_chk_fail': 0x4006B8,
}


def run(path, key):
    emu = Emu(path, base=0)          # non-PIE, absolute 0x400000
    io = {'in': list(key.encode() + b'\n'), 'out': bytearray(), 'exit': None}

    @emu.stub(PLT['getchar'])
    def _getchar(e):
        return io['in'].pop(0) if io['in'] else 0x0A

    @emu.stub(PLT['putchar'])
    def _putchar(e):
        io['out'].append(e.arg(0) & 0xFF)
        return e.arg(0)

    @emu.stub(PLT['puts'])
    def _puts(e):
        io['out'] += e.read_cstr(e.arg(0)) + b'\n'
        return 1

    @emu.stub(PLT['printf'])
    def _printf(e):
        io['out'] += e.read_cstr(e.arg(0))
        return 1

    @emu.stub(PLT['ptrace'])
    def _ptrace(e):
        return 0                     # nobody is tracing us

    @emu.stub(PLT['close'])
    def _close(e):
        return 0xFFFFFFFFFFFFFFFF    # EBADF, i.e. fd 3 was not open

    @emu.stub(PLT['strncmp'])
    def _strncmp(e):
        a = e.read_cstr(e.arg(0))[:e.arg(2)]
        b = e.read_cstr(e.arg(1))[:e.arg(2)]
        return 0 if a == b else (1 if a > b else 0xFFFFFFFFFFFFFFFF)

    @emu.stub(PLT['exit'])
    def _exit(e):
        io['exit'] = e.arg(0) & 0xFFFFFFFF
        e.uc.emu_stop()

    emu.abort_at(PLT['stack_chk_fail'], 'stack_chk_fail')
    emu.call(MAIN, 0, 0, 0)
    text = io['out'].decode('latin1')
    return io['exit'], text[text.rindex('fool:') + 5:].strip() if 'fool:' in text else text


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    keys = sys.argv[2:] or [k for k, _ in solve.keygen(seed=0)] + ['1111-1111-1111-1111']
    bad = 0
    for key in keys:
        status, msg = run(path, key)
        good = status is None
        bad += good != solve.check(key)
        print(f'{key}  exit={"-" if status is None else status}  {msg[:52]}')
    print(f'\n{len(keys) - bad}/{len(keys)} agree with solve.check()')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
