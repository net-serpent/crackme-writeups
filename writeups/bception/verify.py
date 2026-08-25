#!/usr/bin/env python3
"""verify.py ./uck [NUMBER ...]

Runs the binary's own interpreter (fcn.00400837) on the real bytecode under
Unicorn, with the context laid out exactly the way main() lays it out, and
compares against the python reimplementation in solve.py.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

INTERP, CODE, CLEN = 0x400837, 0x400FE0, 0x55
CTX_SIZE = 0x140
SP_OFF, PC_OFF, MEM_OFF = 0x114, 0x118, 0x12


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    emu = Emu(sys.argv[1], base=0)
    ctx = emu.alloc(bytes(CTX_SIZE))
    assert bytes(emu.uc.mem_read(CODE, CLEN)) == solve.CODE, 'bytecode drifted'

    answer = solve.brute()
    values = [int(a, 0) for a in sys.argv[2:]] or [answer, answer ^ 1, 0, 1094861636]
    bad = 0
    for v in values:
        emu.uc.mem_write(ctx, bytes(CTX_SIZE))
        emu.uc.mem_write(ctx + MEM_OFF, struct.pack('<I', v) + b'\x04')
        emu.uc.mem_write(ctx + SP_OFF, (4).to_bytes(4, 'little'))
        rv = emu.call(INTERP, ctx, CODE, CLEN)
        got = rv if isinstance(rv, str) else struct.unpack('<i', struct.pack('<I', rv & 0xFFFFFFFF))[0]
        want = solve.vm(v)
        bad += got != want
        verdict = 'Well done :-D' if got == 4 else 'And... you failed !'
        print(f'{v:>11} (0x{v:08x})  binary={got}  solve.vm={want}  -> {verdict}')
    print(f'\n{len(values) - bad}/{len(values)} agree with the reimplementation')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
