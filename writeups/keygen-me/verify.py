#!/usr/bin/env python3
"""verify.py [task.unpacked]

Two checks against the binaries, not against my reading of them:

1. Unpack: decrypt the dropper's blob with the reimplemented glibc rand and
   confirm it parses as an ELF. A wrong rand or key would not produce valid
   headers. If a saved inner.elf is present, confirm they match byte for byte.
2. The xor transform: call fcn.2549 in the inner ELF under Unicorn on a test
   string and confirm it xors every byte with 0x42, the constant the topic
   chain relies on. MD5 and SHA256 are the standard algorithms, so hashlib
   agrees with the OpenSSL the binary links.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from ucload import Emu, parse_image                     # noqa: E402
import solve                                            # noqa: E402

XFORM = 0x2549                       # fcn.2549(std::string *s, int key)
THUNK_A, THUNK_B = 0x2450, 0x22F0    # string::operator[] and size(), order tbd


def check_xform(path, sample=b'0123456789abcdef'):
    """Drive fcn.2549 with a real std::string; it should xor each byte by 0x42.

    The two std::string thunks it calls are stubbed. Their order is resolved by
    trying both assignments and keeping whichever makes the transform run.
    """
    for idx_thunk, size_thunk in ((THUNK_A, THUNK_B), (THUNK_B, THUNK_A)):
        emu = Emu(path, base=0)
        sp = emu.alloc(bytes(0x20))
        buf = sp + 0x10
        emu.write_word(sp, buf)                          # data ptr
        emu.write_word(sp + 8, len(sample))              # length
        emu.uc.mem_write(buf, sample + b'\0')

        @emu.stub(idx_thunk)
        def _index(e):
            return e.read_word(e.arg(0)) + e.arg(1)      # &data[i]

        @emu.stub(size_thunk)
        def _size(e):
            return e.read_word(e.arg(0) + 8)

        rv = emu.call(XFORM, sp, 0x42)
        if isinstance(rv, str):
            continue
        got = bytes(emu.uc.mem_read(buf, len(sample)))
        if got == bytes(b ^ 0x42 for b in sample):
            return True
    return False


def main():
    here = Path(__file__).resolve().parent
    unpacked = sys.argv[1] if len(sys.argv) > 1 else str(here / 'task.unpacked')

    elf = solve.inner_elf(unpacked)
    ok_elf = elf[:4] == b'\x7fELF'
    print(f'1. unpack: inner ELF magic {elf[:4]!r}  valid={ok_elf}  ({len(elf)} bytes)')
    tmp = here / '.inner_check'
    tmp.write_bytes(elf)
    try:
        segs = parse_image(str(tmp))['chunks']
        print(f'   parses as ELF: {len(segs)} PT_LOAD segments')
    except Exception as e:
        ok_elf = False
        print(f'   parse failed: {e}')
    finally:
        tmp.unlink()

    inner = here / 'inner.elf'
    ok_xform = None
    if inner.exists():
        if inner.read_bytes() == elf:
            print('   matches saved inner.elf: True')
        ok_xform = check_xform(str(inner))
    print(f'2. fcn.2549 xors with 0x42: {ok_xform}')

    print(f'\nname:  {solve.NAME}')
    print(f'topic: {solve.topic()}')
    print(f'flag:  {solve.flag()}')
    return 0 if ok_elf and ok_xform else 1


if __name__ == '__main__':
    raise SystemExit(main())
