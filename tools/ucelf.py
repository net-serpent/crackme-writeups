#!/usr/bin/env python3
"""Call one function out of a Linux ELF under Unicorn, so I can check an
algorithm against the real code without running the sample.

Maps PT_LOAD at a fixed base, swaps imports for python stubs, sets up SysV
args. pip install unicorn pyelftools.
"""
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE, UcError
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    UC_X86_REG_RIP, UC_X86_REG_FS_BASE, UC_X86_REG_EAX, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_GS_BASE,
)

ARG_REGS = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
            UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)


class Emu:
    BASE = 0x100000
    IMAGE = 0x100000
    STACK_TOP = 0x7F0000
    FS_BASE = 0x800000
    HEAP = 0x900000
    HEAP_SIZE = 0x10000
    RET_MAGIC = 0xDEAD0000

    def __init__(self, path, base=BASE):
        self.base = base
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            self.bits = elf.elfclass
            self.uc = uc = Uc(UC_ARCH_X86,
                              UC_MODE_32 if self.bits == 32 else UC_MODE_64)
            loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
            lo = min(s['p_vaddr'] for s in loads) & ~0xFFF
            hi = max(s['p_vaddr'] + s['p_memsz'] for s in loads)
            # non-PIE images sit at 0x400000, so map what the file asks for
            self.lo, self.hi = lo, (hi + 0xFFF) & ~0xFFF
            span = max(self.hi - lo, self.IMAGE)
            uc.mem_map(base + lo, span)
            for seg in loads:
                uc.mem_write(base + seg['p_vaddr'], seg.data())
        uc.mem_map(self.STACK_TOP - 0x10000, 0x20000)
        uc.mem_map(self.FS_BASE, 0x1000)
        uc.mem_map(self.HEAP, self.HEAP_SIZE)
        uc.mem_map(self.RET_MAGIC & ~0xFFF, 0x1000)
        # canary lives at fs:0x28 on x86-64 and gs:0x14 on x86
        uc.reg_write(UC_X86_REG_FS_BASE, self.FS_BASE)
        uc.reg_write(UC_X86_REG_GS_BASE, self.FS_BASE)
        uc.mem_write(self.FS_BASE + 0x14, b'\x44\x33\x22\x11')
        uc.mem_write(self.FS_BASE + 0x28, b'\x88\x77\x66\x55\x44\x33\x22\x11')
        self.stubs = {}       # rel addr -> fn(emu), returns rax or None
        self.aborts = {}      # rel addr -> label
        self._brk = self.HEAP
        uc.hook_add(UC_HOOK_CODE, self._hook,
                    begin=base + lo, end=base + lo + span)

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
        if self.bits == 32:
            return self.read_word(self.uc.reg_read(UC_X86_REG_ESP) + i * 4)
        return self.uc.reg_read(ARG_REGS[i])

    def stub(self, addr):
        """@emu.stub(0x11f0) over a python replacement for that PLT entry."""
        def deco(fn):
            self.stubs[self.base + addr] = fn
            return fn
        return deco

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
        sp_reg = UC_X86_REG_ESP if self.bits == 32 else UC_X86_REG_RSP
        sp = uc.reg_read(sp_reg)
        ret_to = self.read_word(sp)
        uc.reg_write(sp_reg, sp + self.wsize)
        rv = fn(self)
        if rv is not None:
            uc.reg_write(UC_X86_REG_EAX if self.bits == 32 else UC_X86_REG_RAX,
                         rv & (2**self.bits - 1))
        uc.reg_write(UC_X86_REG_EIP if self.bits == 32 else UC_X86_REG_RIP, ret_to)

    def call(self, addr, *args, count=1_000_000):
        """rel addr in, rax out. Returns 'abort:<label>' if it bailed."""
        self._abort = None
        uc = self.uc
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
