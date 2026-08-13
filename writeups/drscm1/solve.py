"""drscm1 by Dr.Spliff.

The check never exists in the file. main() copies 56 encrypted bytes out of
.data, runs them through XTEA decryption with a key sitting right next to
them, mprotects the buffer and calls it with three arguments: the {name,
serial} pair and two callbacks.

Decrypted, those 56 bytes are:

    sum = 0; for (p = s->name; *p; p++) sum += (signed char)*p;
    if (sum == s->serial) ok(s);
    bad(s);                                  <- no return, both get called

so serial = sum of the name's bytes, exactly what the author's README says
it is. He asked for a patch instead, which is `patch()` below: nop out the
jne in the plaintext and re-encrypt with the same key, which gives a binary
that takes any serial and still decrypts to something runnable.

    python3 solve.py NAME            serial for that name
    python3 solve.py --dump          the decrypted 56 bytes
    python3 solve.py --patch IN OUT  write a patched binary
"""
import struct
import sys

BLOB_VA, KEY_VA, SIZE_VA = 0x8049A20, 0x8049A5C, 0x8049A58
DELTA = 0x9E3779B9
M = 0xFFFFFFFF


def serial(name: str) -> int:
    """The keygen, all 20 minutes of it."""
    return sum(c - 256 if c >= 128 else c for c in name.encode())


def _rounds(v0, v1, key, decrypt):
    """XTEA with fixed key indices: k2/k3 on one half, k0/k1 on the other.

    The binary only ships the decryption half. Encryption has to walk the same
    sum values back the other way, so it starts at delta and not at zero.
    """
    if decrypt:
        s = (DELTA * 32) & M
        for _ in range(32):
            v1 = (v1 - ((((v0 << 4) + key[2]) ^ (s + v0)) ^ ((v0 >> 5) + key[3]))) & M
            v0 = (v0 - ((((v1 << 4) + key[0]) ^ (s + v1)) ^ ((v1 >> 5) + key[1]))) & M
            s = (s - DELTA) & M
    else:
        s = DELTA & M
        for _ in range(32):
            v0 = (v0 + ((((v1 << 4) + key[0]) ^ (s + v1)) ^ ((v1 >> 5) + key[1]))) & M
            v1 = (v1 + ((((v0 << 4) + key[2]) ^ (s + v0)) ^ ((v0 >> 5) + key[3]))) & M
            s = (s + DELTA) & M
    return v0, v1


def crypt(data: bytes, key, decrypt=True) -> bytes:
    out = b''
    for i in range(0, len(data), 8):
        out += struct.pack('<2I', *_rounds(*struct.unpack('<2I', data[i:i + 8]), key, decrypt))
    return out


def _segments(path):
    from elftools.elf.elffile import ELFFile
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        return [(s['p_vaddr'], s['p_offset'], s['p_filesz'])
                for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']


def _off(path, va):
    for vaddr, offset, size in _segments(path):
        if vaddr <= va < vaddr + size:
            return offset + va - vaddr
    raise KeyError(hex(va))


def load(path):
    raw = open(path, 'rb').read()
    n = raw[_off(path, SIZE_VA)]
    key = struct.unpack('<4I', raw[_off(path, KEY_VA):_off(path, KEY_VA) + 16])
    blob = raw[_off(path, BLOB_VA):_off(path, BLOB_VA) + n]
    return raw, key, blob


def plaintext(path):
    _, key, blob = load(path)
    return crypt(blob, key)


def patch(src, dst):
    """Nop out the `jne` at offset 0x24 of the payload and re-encrypt it."""
    raw, key, blob = load(src)
    plain = bytearray(crypt(blob, key))
    assert plain[0x24:0x26] == b'\x75\x09', 'expected jne +9 at 0x24'
    plain[0x24:0x26] = b'\x90\x90'                       # drop the branch, ok() always runs
    o = _off(src, BLOB_VA)
    out = bytearray(raw)
    out[o:o + len(blob)] = crypt(bytes(plain), key, decrypt=False)
    open(dst, 'wb').write(bytes(out))
    return len(blob)


def main():
    if '--dump' in sys.argv:
        print(plaintext(sys.argv[sys.argv.index('--dump') + 1]).hex(' '))
    elif '--patch' in sys.argv:
        i = sys.argv.index('--patch')
        n = patch(sys.argv[i + 1], sys.argv[i + 2])
        print(f're-encrypted {n} bytes into {sys.argv[i + 2]}')
    else:
        for name in sys.argv[1:] or ['Dr.Spliff', 'neshizoid', 'a']:
            print(f'{name:12} -> {serial(name)}')


if __name__ == '__main__':
    main()
