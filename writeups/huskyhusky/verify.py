#!/usr/bin/env python3
"""verify.py ./crackme [PASSWORD ...]

Boots the whole binary under Unicorn (it is static and talks straight to the
kernel, so read/write/exit are the only things to stub), types a password at
it and reports what it prints.

With no passwords given it also re-derives the multiplier table by probing the
emulated VM one position at a time and checks it against solve.MULTIPLIERS.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
from unicorn import UC_HOOK_CODE, UC_HOOK_INSN          # noqa: E402
from unicorn.x86_const import (                         # noqa: E402
    UC_X86_INS_SYSCALL, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDI,
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RSP,
)
import solve                                            # noqa: E402

ENTRY = 0x4000B0
JNZ_HANDLER = 0x40036A       # the opcode-0x25 handler, edi = the accumulator
VERDICT_PC = 5               # VM pc is already past the branch when it runs


def run(path, password: bytes):
    emu = Emu(path, base=0)
    st = {'in': bytearray(password + b'\n'), 'out': bytearray(), 'acc': None}

    def syscall(uc, _):
        nr = uc.reg_read(UC_X86_REG_RAX)
        buf, cnt = uc.reg_read(UC_X86_REG_RSI), uc.reg_read(UC_X86_REG_RDX)
        if nr == 0:
            data = bytes(st['in'][:cnt])
            del st['in'][:cnt]
            if data:
                uc.mem_write(buf, data)
            uc.reg_write(UC_X86_REG_RAX, len(data))
        elif nr == 1:
            st['out'] += uc.mem_read(buf, cnt)
            uc.reg_write(UC_X86_REG_RAX, cnt)
        elif nr == 60:
            uc.emu_stop()

    def at_verdict(uc, addr, size, _):
        if st['acc'] is None and uc.reg_read(UC_X86_REG_RCX) == VERDICT_PC:
            raw = uc.reg_read(UC_X86_REG_RDI) & 0xFFFFFFFF
            st['acc'] = struct.unpack('<i', struct.pack('<I', raw))[0]

    emu.uc.hook_add(UC_HOOK_INSN, syscall, None, 1, 0, UC_X86_INS_SYSCALL)
    emu.uc.hook_add(UC_HOOK_CODE, at_verdict, begin=JNZ_HANDLER, end=JNZ_HANDLER)
    emu.uc.reg_write(UC_X86_REG_RSP, emu.STACK_TOP - 0x800)
    emu.uc.emu_start(ENTRY, 0, count=20_000_000)
    text = bytes(st['out']).replace(b'\x00', b'').decode('latin1')
    return st['acc'], text.replace('Please enter a password: ', '').strip()


def probe_multipliers(path, n):
    base = run(path, b'A' * n)[0]
    out = []
    for i in range(n):
        g = bytearray(b'A' * n)
        g[i] = ord('B')
        out.append(run(path, bytes(g))[0] - base)
    return out, base - sum(w * ord('A') for w in out)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    if len(sys.argv) > 2:
        for p in sys.argv[2:]:
            acc, msg = run(path, p.encode())
            print(f'{p!r}  A={acc}  ->  {msg!r}')
        return 0

    n = 16
    w, const = probe_multipliers(path, n)
    ok = w == solve.MULTIPLIERS[:n] and -const == solve.TARGET
    print(f'probed multipliers  {w}')
    print(f'probed constant     {const}   ({"matches" if ok else "DOES NOT MATCH"} solve.py)\n')

    bad = 0
    for length in (24, 28, 32):
        key = solve.keygen(length)
        acc, msg = run(path, key)
        good = msg.startswith('Correct')
        bad += not good
        print(f'len {length}: {key.decode():34} A={acc:3}  ->  {msg!r}')
    for junk in (b'password', b'A' * 32):
        acc, msg = run(path, junk)
        bad += msg.startswith('Correct')
        print(f'ctrl:   {junk.decode():34} A={acc:<7} ->  {msg!r}')
    return 1 if bad or not ok else 0


if __name__ == '__main__':
    raise SystemExit(main())
