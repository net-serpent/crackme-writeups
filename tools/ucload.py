#!/usr/bin/env python3
"""Call one function out of an ELF or a PE under Unicorn, so I can check an
algorithm against the real code without running the sample.

Maps the image where it asks to be mapped, swaps imports for python stubs,
sets up the right calling convention. pip install unicorn pyelftools.
"""
from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_X86, UC_ARCH_ARM, UC_MODE_32, UC_MODE_64,
                     UC_MODE_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UcError)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    UC_X86_REG_RIP, UC_X86_REG_FS_BASE, UC_X86_REG_EAX, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_GS_BASE,
)

ARG_REGS = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
            UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)
ARM_ARGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


def parse_image(path):
    """Read an ELF or a PE into {bits, arm, lo, hi, chunks}."""
    with open(path, 'rb') as f:
        magic = f.read(2)
        f.seek(0)
        if magic == b'MZ':
            return _parse_pe(f.read())
        elf = ELFFile(f)
        loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        lo = min(s['p_vaddr'] for s in loads) & ~0xFFF
        hi = max(s['p_vaddr'] + s['p_memsz'] for s in loads)
        return {'bits': elf.elfclass,
                'arm': elf.header.e_machine == 'EM_ARM',
                'lo': lo, 'hi': (hi + 0xFFF) & ~0xFFF,
                'chunks': [(s['p_vaddr'], s.data()) for s in loads]}


def _parse_pe(raw):
    """Minimal PE mapper: headers plus each section at its virtual address."""
    import struct
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    assert raw[pe:pe + 4] == b'PE\0\0', 'not a PE'
    nsect, = struct.unpack_from('<H', raw, pe + 6)
    optsize, = struct.unpack_from('<H', raw, pe + 20)
    magic, = struct.unpack_from('<H', raw, pe + 24)
    bits = 64 if magic == 0x20B else 32
    if bits == 32:
        base, = struct.unpack_from('<I', raw, pe + 52)
    else:
        base, = struct.unpack_from('<Q', raw, pe + 48)
    opt = pe + 24                       # SizeOfImage/SizeOfHeaders live in the
    imgsize, = struct.unpack_from('<I', raw, opt + 56)   # optional header, not
    hdrsize, = struct.unpack_from('<I', raw, opt + 60)   # off the signature
    chunks = [(base, raw[:hdrsize])]
    off = opt + optsize
    for i in range(nsect):
        e = off + i * 40
        vaddr, = struct.unpack_from('<I', raw, e + 12)
        rawsize, = struct.unpack_from('<I', raw, e + 16)
        rawptr, = struct.unpack_from('<I', raw, e + 20)
        if rawsize:
            chunks.append((base + vaddr, raw[rawptr:rawptr + rawsize]))
    dd = opt + (96 if bits == 32 else 112)          # DataDirectory
    imp_rva, imp_size = struct.unpack_from('<II', raw, dd + 8)
    imports = _pe_imports(raw, base, imp_rva, chunks, bits) if imp_rva else {}
    return {'bits': bits, 'arm': False, 'lo': base & ~0xFFF,
            'hi': (base + imgsize + 0xFFF) & ~0xFFF, 'chunks': chunks,
            'imports': imports}


def _pe_imports(raw, base, imp_rva, chunks, bits):
    """{imported name: address of its IAT slot}, so stubs can be hung on it."""
    import struct

    def read(va, n):
        for cbase, data in chunks:
            if cbase <= va < cbase + len(data):
                off = va - cbase
                return data[off:off + n]
        return b''

    def cstr(va):
        out = b''
        while True:
            c = read(va + len(out), 1)
            if not c or c == b'\0':
                return out
            out += c

    width = 4 if bits == 32 else 8
    fmt = '<I' if bits == 32 else '<Q'
    high = 0x80000000 if bits == 32 else 0x8000000000000000
    out, i = {}, 0
    while True:
        d = read(base + imp_rva + i * 20, 20)
        if len(d) < 20:
            break
        lookup, _, _, name_rva, first = struct.unpack('<IIIII', d)
        if not (lookup or first):
            break
        i += 1
        names = lookup or first
        k = 0
        while True:
            ent = read(base + names + k * width, width)
            if len(ent) < width:
                break
            val, = struct.unpack(fmt, ent)
            if not val:
                break
            slot = base + first + k * width
            if val & high:
                out[f'#{val & 0xFFFF}'] = slot          # imported by ordinal
            else:
                out[cstr(base + val + 2).decode('latin1')] = slot
            k += 1
    return out


class Emu:
    BASE = 0x100000
    IMAGE = 0x100000
    STACK_TOP = 0x7F0000
    FS_BASE = 0x800000
    HEAP = 0x900000
    HEAP_SIZE = 0x10000
    RET_MAGIC = 0xDEAD0000
    FAKE_IMPORTS = 0xF0000000

    def __init__(self, path, base=BASE, thumb=True):
        self.base = base
        img = parse_image(path)
        self.bits, self.arm, self.thumb = img['bits'], img['arm'], thumb
        if self.arm:
            self.uc = uc = Uc(UC_ARCH_ARM,
                              UC_MODE_THUMB if thumb else UC_MODE_ARM)
        else:
            self.uc = uc = Uc(UC_ARCH_X86,
                              UC_MODE_32 if self.bits == 32 else UC_MODE_64)
        lo = img['lo']
        # non-PIE images sit at 0x400000, PE ones usually higher; map what the
        # file asks for rather than a fixed window
        self.lo, self.hi = lo, img['hi']
        span = max(self.hi - lo, self.IMAGE)
        uc.mem_map(base + lo, span)
        for vaddr, data in img['chunks']:
            uc.mem_write(base + vaddr, data)
        uc.mem_map(self.STACK_TOP - 0x10000, 0x20000)
        uc.mem_map(self.FS_BASE, 0x1000)
        uc.mem_map(self.HEAP, self.HEAP_SIZE)
        uc.mem_map(self.RET_MAGIC & ~0xFFF, 0x1000)
        uc.mem_map(self.FAKE_IMPORTS, 0x1000)
        if not self.arm and self.bits == 64:
            # stack canary at fs:0x28; unicorn only takes these in 64 bit mode
            uc.reg_write(UC_X86_REG_FS_BASE, self.FS_BASE)
            uc.reg_write(UC_X86_REG_GS_BASE, self.FS_BASE)
            uc.mem_write(self.FS_BASE + 0x28, b'\x88\x77\x66\x55\x44\x33\x22\x11')
        self.stubs = {}       # rel addr -> fn(emu), returns rax or None
        self.aborts = {}      # rel addr -> label
        self.imports = img.get('imports', {})
        self.stdcall = {}     # stub addr -> argument count to pop on return
        self._fake = self.FAKE_IMPORTS
        self._brk = self.HEAP
        uc.hook_add(UC_HOOK_CODE, self._hook,
                    begin=base + lo, end=base + lo + span)
        # import stubs live outside the image, so they need their own hook
        uc.hook_add(UC_HOOK_CODE, self._hook,
                    begin=self.FAKE_IMPORTS, end=self.FAKE_IMPORTS + 0x1000)

    def alloc(self, data: bytes, align=16) -> int:
        addr = self._brk
        self.uc.mem_write(addr, data)
        self._brk += (len(data) + align - 1) & ~(align - 1)
        return addr

    def reset_heap(self):
        self._brk = self.HEAP

    def read_cstr(self, ptr: int, limit=4096) -> bytes:
        out = bytearray()
        while len(out) < limit:
            c = self.uc.mem_read(ptr + len(out), 1)[0]
            if c == 0:
                break
            out.append(c)
        return bytes(out)

    def read_u64(self, addr):
        return int.from_bytes(self.uc.mem_read(addr, 8), 'little')

    def write_u64(self, addr, val):
        self.uc.mem_write(addr, (val & (2**64 - 1)).to_bytes(8, 'little'))

    @property
    def wsize(self):
        return self.bits // 8

    def read_word(self, addr):
        return int.from_bytes(self.uc.mem_read(addr, self.wsize), 'little')

    def write_word(self, addr, val):
        self.uc.mem_write(addr, (val & (2**self.bits - 1)).to_bytes(self.wsize, 'little'))

    def arg(self, i):
        """Call this from inside a stub: the return address is already popped,
        so on x86 esp points straight at the first cdecl argument."""
        if self.arm:
            return self.uc.reg_read(ARM_ARGS[i])
        if self.bits == 32:
            return self.read_word(self.uc.reg_read(UC_X86_REG_ESP) + i * 4)
        return self.uc.reg_read(ARG_REGS[i])

    def stub(self, addr):
        """@emu.stub(0x11f0) over a python replacement for that PLT entry."""
        def deco(fn):
            self.stubs[self.base + addr] = fn
            return fn
        return deco

    def stub_import(self, name, fn=None, argc=0):
        """Point an IAT slot at an address of our own and stub that.

        PE calls go through `call [iat]`, so there is nothing at a fixed
        address to hook the way a PLT thunk gives you. Write a made up
        address into the slot instead and hang the python function there.
        """
        def attach(f):
            slot = self.imports[name]
            addr = self._fake
            self._fake += 0x10
            self.write_word(slot, addr)
            self.stubs[addr] = f
            self.stdcall[addr] = argc      # win32 callees clean their own args
            return f
        return attach(fn) if fn else attach

    def abort_at(self, addr, label):
        self.aborts[self.base + addr] = label

    def _hook(self, uc, addr, size, _):
        if addr in self.aborts:
            self._abort = self.aborts[addr]
            uc.emu_stop()
            return
        fn = self.stubs.get(addr)
        if fn is None:
            return
        if self.arm:
            # AAPCS: the return address is in lr, args are already in r0..r3.
            # Writing pc from inside a code hook does not reliably break out of
            # an already translated block on arm, so stop here and let call()
            # restart at the return address.
            ret_to = uc.reg_read(UC_ARM_REG_LR)
            rv = fn(self)
            if rv is not None:
                uc.reg_write(UC_ARM_REG_R0, rv & 0xFFFFFFFF)
            self._resume = ret_to & ~1
            uc.emu_stop()
            return
        sp_reg = UC_X86_REG_ESP if self.bits == 32 else UC_X86_REG_RSP
        sp = uc.reg_read(sp_reg)
        ret_to = self.read_word(sp)
        uc.reg_write(sp_reg, sp + self.wsize)
        rv = fn(self)
        if rv is not None:
            uc.reg_write(UC_X86_REG_EAX if self.bits == 32 else UC_X86_REG_RAX,
                         rv & (2**self.bits - 1))
        uc.reg_write(UC_X86_REG_EIP if self.bits == 32 else UC_X86_REG_RIP, ret_to)
        argc = self.stdcall.get(addr, 0)
        if argc:
            uc.reg_write(sp_reg, uc.reg_read(sp_reg) + argc * self.wsize)

    def call(self, addr, *args, count=1_000_000):
        """rel addr in, rax out. Returns 'abort:<label>' if it bailed."""
        self._abort = None
        self._resume = None
        uc = self.uc
        if self.arm:
            uc.reg_write(UC_ARM_REG_SP, self.STACK_TOP)
            uc.reg_write(UC_ARM_REG_LR, self.RET_MAGIC)
            for reg, val in zip(ARM_ARGS, args):
                uc.reg_write(reg, val)
            pc = self.base + addr
            if self.thumb:
                pc |= 1
            budget = count
            while budget > 0:
                self._resume = None
                try:
                    uc.emu_start(pc, self.RET_MAGIC, count=budget)
                except UcError as e:
                    return f'abort:unicorn:{e}'
                if self._abort:
                    return f'abort:{self._abort}'
                if self._resume is None:
                    break
                pc = self._resume | 1 if self.thumb else self._resume
                budget -= 1
            return uc.reg_read(UC_ARM_REG_R0)
        if self.bits == 32:
            sp = self.STACK_TOP - 4 * len(args)
            for i, val in enumerate(args):
                self.write_word(sp + 4 + i * 4, val)
            self.write_word(sp, self.RET_MAGIC)
            uc.reg_write(UC_X86_REG_ESP, sp)
        else:
            uc.reg_write(UC_X86_REG_RSP, self.STACK_TOP)
            self.write_u64(self.STACK_TOP, self.RET_MAGIC)
            for reg, val in zip(ARG_REGS, args):
                uc.reg_write(reg, val)
        try:
            uc.emu_start(self.base + addr, self.RET_MAGIC, count=count)
        except UcError as e:
            return f'abort:unicorn:{e}'
        if self._abort:
            return f'abort:{self._abort}'
        return uc.reg_read(UC_X86_REG_EAX if self.bits == 32 else UC_X86_REG_RAX)


def cxx_string(emu: Emu, s: bytes) -> int:
    """libstdc++ std::string: {char *data; size_t size; char sso[16];}"""
    data = emu.alloc(s + b'\0')
    return emu.alloc(data.to_bytes(8, 'little') + len(s).to_bytes(8, 'little') + bytes(16))


def strtol(text: bytes, base=10):
    """(value, chars consumed, errno), same rules as the C one."""
    t = text.decode('latin1')
    i = 0
    while i < len(t) and t[i] in ' \t\n\v\f\r':
        i += 1
    start = i
    if i < len(t) and t[i] in '+-':
        i += 1
    d0 = i
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'[:base]
    while i < len(t) and t[i].lower() in digits:
        i += 1
    if i == d0:
        return 0, 0, 0                      # nothing parsed -> endptr == nptr
    val = int(t[start:i], base)
    if not -(1 << 63) <= val < (1 << 63):
        return ((1 << 63) - 1 if val > 0 else -(1 << 63)), i, 34   # ERANGE
    return val, i, 0
