#!/usr/bin/env python3
"""Emulate KataVM_L1's check function and trace its VM at the bytecode level."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucelf import Emu
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RDX, UC_X86_REG_RAX, UC_X86_REG_RDI

BIN = str(Path(__file__).resolve().parent / 'KataVM_Level_1' / 'KataVM_L1')
CHECK, FETCH, CMP_IMM = 0x12D0, 0x134E, 0x1526
T = {'puts': 0x10C0, 'write': 0x10D0, 'chk': 0x10E0, 'alarm': 0x10F0,
     'read': 0x1100, 'signal': 0x1110, 'memcpy': 0x1120, 'getc': 0x1130}


def run(data: bytes, trace=False, cmps=False, slots=4):
    emu = Emu(BIN, base=0)
    st = {'in': bytearray(data), 'out': bytearray(), 'trace': [], 'cmps': []}

    @emu.stub(T['write'])
    def _write(e):
        st['out'] += e.uc.mem_read(e.arg(1), e.arg(2))
        return e.arg(2)

    @emu.stub(T['read'])
    def _read(e):
        n = e.arg(2)
        d = bytes(st['in'][:n])
        del st['in'][:n]
        if d:
            e.uc.mem_write(e.arg(1), d)
        return len(d)

    @emu.stub(T['memcpy'])
    def _memcpy(e):
        d, s, n = e.arg(0), e.arg(1), e.arg(2)
        if n:
            e.uc.mem_write(d, bytes(e.uc.mem_read(s, n)))
        return d

    @emu.stub(T['puts'])
    def _puts(e):
        st['out'] += e.read_cstr(e.arg(0)) + b'\n'
        return 1

    for k in ('alarm', 'signal'):
        emu.stub(T[k])(lambda e: 0)
    emu.abort_at(T['chk'], 'stack_chk_fail')

    if trace:
        def spy(uc, ad, sz, _):
            rdx, rsp = uc.reg_read(UC_X86_REG_RDX), uc.reg_read(UC_X86_REG_RSP)
            st['trace'].append((rdx, bytes(uc.mem_read(rdx, 12)),
                                [int.from_bytes(uc.mem_read(rsp + i * 4, 4), 'little')
                                 for i in range(slots)]))
        emu.uc.hook_add(UC_HOOK_CODE, spy, begin=FETCH, end=FETCH)
    if cmps:
        def spyc(uc, ad, sz, _):
            rsp = uc.reg_read(UC_X86_REG_RSP)
            i = uc.reg_read(UC_X86_REG_RAX) & 3
            st['cmps'].append((i, int.from_bytes(uc.mem_read(rsp + i * 4, 4), 'little'),
                               uc.reg_read(UC_X86_REG_RDI) & 0xFFFFFFFF))
        emu.uc.hook_add(UC_HOOK_CODE, spyc, begin=CMP_IMM, end=CMP_IMM)
    rv = emu.call(CHECK, count=50_000_000)
    return rv, st


def full_trace(inp: bytes, slots=8):
    """One entry per VM step: (bytecode pc, instruction bytes, slot ring)."""
    _, st = run(inp, trace=True, slots=slots)
    return st['trace']


if __name__ == '__main__':
    rv, st = run(b'ABCDEFGHIJKLMNOP\n', trace=True, cmps=True)
    log = st['trace']
    base = log[0][0]
    from collections import Counter
    print(f'VM steps: {len(log)}   rv={rv}')
    print('opcodes:', Counter(i[1][0] for i in log).most_common(14))
    print('compares:', [(i, hex(a), hex(e)) for i, a, e in st['cmps']])
    print('\nfirst 30 steps:')
    for rdx, ins, regs in log[:30]:
        print(f'  +{rdx - base:05x}  op={ins[0]:02x} arg={ins[1]:02x} {ins[2:6].hex()}  '
              f'r={[f"{x:08x}" for x in regs]}')
