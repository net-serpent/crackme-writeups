#!/usr/bin/env python3
"""verify.py Arm_crackme/arm_crack1 [WORD ...]

Runs the real ARM main() under Unicorn in Thumb mode with libc stubbed, types
each candidate at the fgets stub and reports what the binary prints.

ptrace returns 0 so the anti-debug is satisfied, and alarm/signal are no-ops,
which is the only reason a 50 second timeout does not matter here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

MAIN = 0x88D4
PLT = {
    'abort': 0x84E4, 'signal': 0x84FC, 'ptrace': 0x8518, 'fgets': 0x8524,
    'system': 0x8530, 'memcpy': 0x853C, 'alarm': 0x8548, 'printf': 0x8554,
    'malloc': 0x8560, 'stack_chk_fail': 0x856C, 'puts': 0x8578, 'exit': 0x8584,
}


def run(path, word: bytes):
    emu = Emu(path, base=0)
    st = {'out': [], 'in': word + b'\n', 'exit': None}

    @emu.stub(PLT['malloc'])
    def _malloc(e):
        return e.alloc(bytes(e.arg(0) + 16))

    @emu.stub(PLT['memcpy'])
    def _memcpy(e):
        dst, src, n = e.arg(0), e.arg(1), e.arg(2)
        if n:
            e.uc.mem_write(dst, bytes(e.uc.mem_read(src, n)))
        return dst

    @emu.stub(PLT['puts'])
    def _puts(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 1

    @emu.stub(PLT['printf'])
    def _printf(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 1

    @emu.stub(PLT['system'])
    def _system(e):
        st['out'].append(f'<system {e.read_cstr(e.arg(0)).decode("latin1")!r}>')
        return 0

    @emu.stub(PLT['fgets'])
    def _fgets(e):
        buf, size = e.arg(0), e.arg(1)
        data = st['in'][:size - 1] + b'\0'
        e.uc.mem_write(buf, data)
        return buf

    @emu.stub(PLT['ptrace'])
    def _ptrace(e):
        return 0                       # nobody is tracing us

    for noop in ('alarm', 'signal'):
        emu.stub(PLT[noop])(lambda e: 0)

    @emu.stub(PLT['exit'])
    def _exit(e):
        st['exit'] = e.arg(0)
        e.uc.emu_stop()

    emu.abort_at(PLT['stack_chk_fail'], 'stack_chk_fail')
    emu.abort_at(PLT['abort'], 'abort')
    rv = emu.call(MAIN, 0, 0, 0)
    return st, rv


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    want = solve.flag(path)
    words = [w.encode() for w in sys.argv[2:]] or [want, solve.cipher(path), b'hello_world!']
    bad = 0
    for w in words:
        st, rv = run(path, w)
        text = ' | '.join(x.strip() for x in st['out'] if 'WELCOME' not in x)
        ok = 'WAY TO GO' in text
        bad += ok != (w == want)
        print(f'{w.decode("latin1"):14} exit={st["exit"]}  rv={rv}  {text[:70]}')
    print(f'\nflag: {want.decode()}   ({len(words) - bad}/{len(words)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
