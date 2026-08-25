#!/usr/bin/env python3
"""verify.py ./tiny-crackme [PASSWORD ...]
verify.py ./tiny-crackme --search      recover the password from scratch

Runs the whole thing in Unicorn. It is a freestanding 32-bit ELF that only
uses int 0x80, so read/write/exit/ptrace are the entire runtime. ptrace
returns 0, which is what an untraced process gets, so the anti-debug check
passes honestly.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
from unicorn import UC_HOOK_CODE, UC_HOOK_INTR          # noqa: E402
from unicorn.x86_const import (                         # noqa: E402
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESP,
)
import solve                                            # noqa: E402

ENTRY = 0x200008
XOR_SITE = 0x2000B1       # xor ebx, [0x200296], with ebx = expected value
PERM = {0: 2, 1: 3, 2: 0, 3: 1}


def run(path, password: bytes):
    emu = Emu(path, base=0)
    st = {'in': bytearray(password + b'\n'), 'out': bytearray(), 'ebx': None}

    def intr(uc, no, _):
        if no != 0x80:
            return
        nr = uc.reg_read(UC_X86_REG_EAX)
        a, b, c = (uc.reg_read(r) for r in (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX))
        if nr == 3:                                     # read
            data = bytes(st['in'][:c])
            del st['in'][:c]
            if data:
                uc.mem_write(b, data)
            uc.reg_write(UC_X86_REG_EAX, len(data))
        elif nr == 4:                                   # write
            st['out'] += uc.mem_read(b, c)
            uc.reg_write(UC_X86_REG_EAX, c)
        elif nr == 1:                                   # exit
            uc.emu_stop()
        elif nr == 26:                                  # ptrace(TRACEME) -> 0
            uc.reg_write(UC_X86_REG_EAX, 0)
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)

    def at_xor(uc, addr, size, _):
        st['ebx'] = uc.reg_read(UC_X86_REG_EBX)

    emu.uc.hook_add(UC_HOOK_INTR, intr)
    emu.uc.hook_add(UC_HOOK_CODE, at_xor, begin=XOR_SITE, end=XOR_SITE)
    emu.uc.reg_write(UC_X86_REG_ESP, emu.STACK_TOP - 0x400)
    emu.uc.emu_start(ENTRY, 0, count=2_000_000)
    text = bytes(st['out']).decode('latin1')
    tail = text.split('Password :')[-1].strip() if 'Password :' in text else text
    return st['ebx'], tail


def search(path):
    """Recover every accepted password by probing the transform."""
    base = b'ABCD'
    tab = [{v: run(path, bytes(base[:i]) + bytes([v]) + bytes(base[i + 1:]))[0]
            for v in range(256)} for i in range(4)]

    def f(i, v):
        return (tab[i][v] >> (8 * PERM[i])) & 0xFF

    cyc_ac = [(a, f(0, a)) for a in range(256) if f(2, f(0, a)) == a]
    cyc_bd = [(b, f(1, b)) for b in range(256) if f(3, f(1, b)) == b]
    return sorted(bytes([a, b, c, d]) for a, c in cyc_ac for b, d in cyc_bd)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]

    if '--search' in sys.argv:
        found = search(path)
        printable = [p for p in found if all(0x20 <= c < 0x7F for c in p)]
        print(f'{len(found)} accepted values, {len(printable)} of them printable')
        print('  ' + ' '.join(p.decode() for p in printable))
        ok = solve.PASSWORD in found and printable == sorted(solve.PRINTABLE)
        print(f'\nsolve.py agrees: {ok}')
        return 0 if ok else 1

    for p in sys.argv[2:] or [solve.PASSWORD, b'boom', b'AAAA']:
        pw = p if isinstance(p, bytes) else p.encode()
        ebx, msg = run(path, pw)
        verdict = next((ln.strip() for ln in msg.splitlines() if ln.strip()), '')
        print(f'{pw.decode():8} expected={ebx:#010x} ({struct.pack("<I", ebx)!r})  {verdict}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
