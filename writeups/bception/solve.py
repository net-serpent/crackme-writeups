#!/usr/bin/env python3
"""ELF - BCeption. The password is an unsigned int fed to a tiny bytecode VM.

main() scanf("%u")s a number, splits it into 4 bytes, drops them plus a length
byte into the VM's data memory, sets the VM stack pointer to 4, then runs 85
bytes of bytecode at 0x400fe0. Success is a return value of exactly 4.

Two things fall out of the interpreter (fcn.00400837):

  * the return value is `number of correct bytes`, which makes the VM its own
    oracle: 4 * 256 probes are enough without understanding the bytecode
  * the actual check is a chain of XOR constants, trivially invertible

Both are implemented below and cross-checked against each other.

    python3 solve.py          answer + bytecode listing
    python3 solve.py -d       listing only
"""
import struct
import sys

CODE = bytes.fromhex(          # 0x55 bytes at 0x400fe0
    '1400010f04150f0e5314011402140314040108130109'
    '37010a01010bf0010c0f010d900107ad15270e2c03ea'
    '07190107e915170e3703ea074807490107cb15470e44'
    '03ea073d073c073901071615370e5303ea160e')

MNEMONIC = {
    0x01: 'mov  r%(arg)d, %(imm)#04x',
    0x03: 'add  r%(hi)d, r%(lo)d',
    0x07: 'xor  r%(hi)d, r%(lo)d',
    0x0E: 'jne  %(arg)#04x',
    0x14: 'pop  r%(arg)d',
    0x15: 'cmp  r%(hi)d, r%(lo)d',
    0x16: 'ret  r%(arg)d',
}


def disasm(code=CODE):
    pc, out = 0, []
    while pc < len(code):
        op, arg = code[pc], code[pc + 1]
        f = {'arg': arg, 'hi': arg >> 4, 'lo': arg & 15,
             'imm': code[pc + 2] if op == 0x01 else 0}
        text = MNEMONIC.get(op, 'op%02x %#04x' % (op, arg)) % f
        out.append((pc, code[pc:pc + (3 if op == 0x01 else 2)], text))
        pc += 3 if op == 0x01 else 2
    return out


def vm(value, code=CODE):
    """The interpreter, reimplemented. Returns what fcn.00400837 returns."""
    r = [0] * 18                       # r0..r15 plus the eq/lt/gt flags at 15..17
    mem = list(struct.pack('<I', value)) + [4] + [0] * 251
    sp, pc = 4, 0
    EQ, LT, GT = 0x0F, 0x10, 0x11
    while pc + 1 < len(code):
        op, arg = code[pc], code[pc + 1]
        hi, lo = arg >> 4, arg & 15
        if op == 0x01:
            r[arg] = code[pc + 2]
            pc += 1
        elif op == 0x03:
            r[hi] = (r[hi] + r[lo]) & 0xFF
        elif op == 0x07:
            r[hi] ^= r[lo]
        elif op == 0x0E:
            if not r[EQ]:
                pc = arg - 2
        elif op == 0x14:
            r[arg] = mem[sp]
            sp -= 1
        elif op == 0x15:
            a, b = r[hi], r[lo]
            r[EQ] = r[LT] = r[GT] = 0
            if a == b:
                r[EQ] = 1
            elif a - b > 0:
                r[LT] = 1
            else:
                r[GT] = 1
        elif op == 0x16:
            return r[arg]
        pc += 2
    return -1                          # ran off the end


def brute():
    """Recover the password one byte at a time off the return-value leak."""
    val = 0
    for shift in (0, 8, 16, 24):
        base = vm(val)
        for b in range(256):
            cand = (val & ~(0xFF << shift) | (b << shift)) & 0xFFFFFFFF
            if vm(cand) > base:
                val = cand
                break
    return val


def main():
    listing = disasm()
    if '-d' not in sys.argv:
        answer = brute()
        print(f'password: {answer} (0x{answer:08x})   vm() returns {vm(answer)}\n')
    for pc, raw, text in listing:
        print(f'  {pc:02x}:  {raw.hex(" "):9}  {text}')


if __name__ == '__main__':
    main()
