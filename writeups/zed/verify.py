#!/usr/bin/env python3
"""verify.py ./ZED-unpacked.bin [SERIAL ...]

Runs the unpacked binary's real main() under Unicorn with libc stubbed and the
candidate fed through scanf. ptrace returns 0, and the sidt anti-VM check reads
whatever Unicorn leaves in the IDTR, which is not 0xff, so both guards pass on
their own terms.

Unpack first if you only have the packed one:  upx -d -o ZED-unpacked.bin ZED-Crackme-x64.bin
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu                                   # noqa: E402
import solve                                            # noqa: E402

MAIN = 0x1343
PLT = {'putchar': 0x7F0, 'puts': 0x800, 'qsort': 0x810, 'strlen': 0x820,
       'stack_chk_fail': 0x830, 'printf': 0x840, 'strcmp': 0x850,
       'tolower': 0x860, 'ptrace': 0x870, 'scanf': 0x880, 'exit': 0x890,
       'ctype_b_loc': 0x8A0}


def ctype_table() -> bytes:
    """glibc's __ctype_b table: one uint16 of flags per byte, indexed -128..255."""
    U, L, A, D, X, S, P, G = 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000
    BL, C, PU, AN = 0x1, 0x2, 0x4, 0x8
    out = bytearray()
    for i in range(-128, 256):
        c, f = i & 0xFF, 0
        if i >= 0:
            ch = chr(c)
            if ch.isupper():  f |= U | A | AN
            if ch.islower():  f |= L | A | AN
            if ch.isdigit():  f |= D | X | AN
            if ch in '0123456789abcdefABCDEF': f |= X
            if ch in ' \t\n\v\f\r': f |= S
            if ch == ' ' or ch == '\t': f |= BL
            if c < 32 or c == 127: f |= C
            if 32 <= c < 127: f |= P
            if 33 <= c < 127: f |= G
            if (33 <= c < 127) and not (f & AN): f |= PU
        out += f.to_bytes(2, 'little')
    return bytes(out)


def run(path, candidate: bytes):
    emu = Emu(path, base=0)
    st = {'out': [], 'in': candidate, 'exit': None}

    @emu.stub(PLT['puts'])
    def _puts(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 1

    @emu.stub(PLT['printf'])
    def _printf(e):
        st['out'].append(e.read_cstr(e.arg(0)).decode('latin1'))
        return 1

    @emu.stub(PLT['putchar'])
    def _putchar(e):
        return e.arg(0)

    @emu.stub(PLT['scanf'])
    def _scanf(e):
        e.uc.mem_write(e.arg(1), st['in'] + b'\0')
        return 1

    @emu.stub(PLT['ptrace'])
    def _ptrace(e):
        return 0

    table = emu.alloc(ctype_table())
    table_ptr = emu.alloc((table + 128 * 2).to_bytes(8, 'little'))

    @emu.stub(PLT['ctype_b_loc'])
    def _ctype_b_loc(e):
        return table_ptr

    @emu.stub(PLT['strcmp'])
    def _strcmp(e):
        a, b = e.read_cstr(e.arg(0)), e.read_cstr(e.arg(1))
        return 0 if a == b else (1 if a > b else 0xFFFFFFFFFFFFFFFF)

    @emu.stub(PLT['strlen'])
    def _strlen(e):
        return len(e.read_cstr(e.arg(0)))

    @emu.stub(PLT['tolower'])
    def _tolower(e):
        c = e.arg(0) & 0xFF
        return ord(chr(c).lower()) if 65 <= c <= 90 else c

    @emu.stub(PLT['exit'])
    def _exit(e):
        st['exit'] = e.arg(0)
        e.uc.emu_stop()

    emu.abort_at(PLT['stack_chk_fail'], 'stack_chk_fail')
    rv = emu.call(MAIN, 1, 0)
    verdict = next((l for l in st['out'] if 'succeed' in l or 'try again' in l
                    or 'detected' in l or 'debugged' in l), '(no verdict)')
    return verdict.strip(), rv


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    want = solve.serial()
    cands = [c.encode() for c in sys.argv[2:]] or [want, solve.MAGIC, want[:-1] + b'X']
    bad = 0
    for c in cands:
        verdict, rv = run(path, c)
        ok = 'succeed' in verdict
        bad += ok != (c == want)
        print(f'{c.decode("latin1"):22} {verdict}')
    print(f'\nserial: {want.decode()}   ({len(cands) - bad}/{len(cands)} as expected)')
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
