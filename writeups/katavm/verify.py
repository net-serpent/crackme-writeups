#!/usr/bin/env python3
"""verify.py [KataVM_Level_1/KataVM_L1] [INPUT ...]

Runs the binary's real main() under Unicorn, types each candidate at it and
prints the verdict main itself prints. Nothing is patched: the VM does its own
15KB of bytecode, and the answer has to satisfy all four of its comparisons.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucelf import Emu                                   # noqa: E402
import solve                                            # noqa: E402
import vmtrace                                          # noqa: E402

MAIN = 0x1170


def run_main(path, data: bytes):
    emu = Emu(path, base=0)
    st = {'in': bytearray(data), 'out': bytearray()}

    @emu.stub(vmtrace.T['read'])
    def _read(e):
        n = e.arg(2)
        d = bytes(st['in'][:n])
        del st['in'][:n]
        if d:
            e.uc.mem_write(e.arg(1), d)
        return len(d)

    @emu.stub(vmtrace.T['write'])
    def _write(e):
        st['out'] += e.uc.mem_read(e.arg(1), e.arg(2))
        return e.arg(2)

    @emu.stub(vmtrace.T['memcpy'])
    def _memcpy(e):
        d, s, n = e.arg(0), e.arg(1), e.arg(2)
        if n:
            e.uc.mem_write(d, bytes(e.uc.mem_read(s, n)))
        return d

    @emu.stub(vmtrace.T['puts'])
    def _puts(e):
        st['out'] += e.read_cstr(e.arg(0)) + b'\n'
        return 1

    @emu.stub(vmtrace.T['getc'])
    def _getc(e):
        return 0xFFFFFFFFFFFFFFFF          # EOF, so main stops draining stdin

    for k in ('alarm', 'signal'):
        emu.stub(vmtrace.T[k])(lambda e: 0)
    emu.abort_at(vmtrace.T['chk'], 'stack_chk_fail')
    emu.call(MAIN, 0, 0, 0, count=50_000_000)
    return bytes(st['out']).decode('latin1')


def main():
    args = [a for a in sys.argv[1:]]
    path = args[0] if args and Path(args[0]).exists() else str(
        Path(__file__).resolve().parent / 'KataVM_Level_1' / 'KataVM_L1')
    cands = [a.encode() for a in args if not Path(a).exists()] or [
        solve.ANSWER, solve.ANSWER[:-1] + b'X', b'A' * 16]
    bad = 0
    for c in cands:
        out = run_main(path, c + b'\n')
        verdict = next((l for l in out.splitlines() if l.startswith('[')), '(no verdict)')
        ok = 'Correct' in verdict
        bad += ok != (c == solve.ANSWER)
        print(f'{c.decode("latin1"):18} {verdict}')
    print(f'\nanswer: {solve.ANSWER.decode()}   '
          f'({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
