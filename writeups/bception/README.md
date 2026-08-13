# ELF - BCeption

Yir, 2018-06-15, Linux x86-64, difficulty 3.0, quality 4.5. "Find the flag ;-)"
<https://crackmes.one/crackme/5b23a35633c5d421d6f6d3e4>

Password: **3735928559**. Which is `0xDEADBEEF`, and the name was the hint:
BC as in bytecode.

## shape of it

`main` is short. It `scanf("%u")`s a number, chops it into four bytes, and
hands them to something else:

```c
unsigned v;  scanf("%u", &v);
b[0] = v & 0xff; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24; b[4] = 4;

vm_init(&ctx);                       // fcn.004007c2, four memsets
memcpy(ctx + 0x12, b, 5);            // data memory
*(int *)(ctx + 0x114) = 4;           // stack pointer

int rc = interpret(&ctx, 0x400fe0, 0x55);   // fcn.00400837
if (rc < 0 || rc != 4) puts("And... you failed !");
else                   puts("[ +   ok     ] > Well done :-D");
```

So `0x400fe0` is 85 bytes of bytecode and `fcn.00400837` is the interpreter.
The context is laid out as 18 one-byte registers, 256 bytes of data memory at
`+0x12`, a stack pointer at `+0x114` and a program counter at `+0x118`.

## the interpreter

`fcn.00400837` is one long `if (op == k1) ... else if (op == k2) ...` chain
against a table of 22 constants at `0x4010cf`, which is just `01 02 03 ... 16`.
Instructions are two bytes, opcode and operand, except opcode 1 which carries
an extra immediate. Most operands are split into nibbles by the two helpers
`fcn.00400f0f` (`>> 4`) and `fcn.00400f21` (`& 0xf`), so `arg = 0xea` means
"register 14, register 10".

The seven the program actually uses:

| op | form | meaning |
|---|---|---|
| 0x01 | 3 bytes | `r[arg] = imm8` |
| 0x03 | | `r[hi] += r[lo]` |
| 0x07 | | `r[hi] ^= r[lo]` |
| 0x0e | | jump to `arg` if the equal flag is clear |
| 0x14 | | `r[arg] = mem[sp]; sp--` |
| 0x15 | | compare `r[hi]` with `r[lo]`, set the eq/lt/gt flags at r15..r17 |
| 0x16 | | return `r[arg]` |

Running off the end of the code returns -1, which is what the `rc < 0` branch
in `main` is for.

The comparison handler is worth a look because it clears all three flag bytes
in a small loop before setting one, which is how you can tell r15/r16/r17 are
flags and not general registers.

## the bytecode

```
  00:  14 00      pop  r0            ; sp starts at 4, so this is the length byte
  02:  01 0f 04   mov  r15, 0x04
  05:  15 0f      cmp  r0, r15
  07:  0e 53      jne  0x53
  09:  14 01      pop  r1            ; input byte 3 (the high one)
  0b:  14 02      pop  r2            ; input byte 2
  0d:  14 03      pop  r3            ; input byte 1
  0f:  14 04      pop  r4            ; input byte 0
  11:  01 08 13   mov  r8, 0x13
  14:  01 09 37   mov  r9, 0x37
  17:  01 0a 01   mov  r10, 0x01
  1a:  01 0b f0   mov  r11, 0xf0
  1d:  01 0c 0f   mov  r12, 0x0f
  20:  01 0d 90   mov  r13, 0x90
  23:  01 07 ad   mov  r7, 0xad
  26:  15 27      cmp  r2, r7
  28:  0e 2c      jne  0x2c
  2a:  03 ea      add  r14, r10      ; r14 counts the bytes that matched
  2c:  07 19      xor  r1, r9
  2e:  01 07 e9   mov  r7, 0xe9
  31:  15 17      cmp  r1, r7
  33:  0e 37      jne  0x37
  35:  03 ea      add  r14, r10
  37:  07 48      xor  r4, r8
  39:  07 49      xor  r4, r9
  3b:  01 07 cb   mov  r7, 0xcb
  3e:  15 47      cmp  r4, r7
  40:  0e 44      jne  0x44
  42:  03 ea      add  r14, r10
  44:  07 3d      xor  r3, r13
  46:  07 3c      xor  r3, r12
  48:  07 39      xor  r3, r9
  4a:  01 07 16   mov  r7, 0x16
  4d:  15 37      cmp  r3, r7
  4f:  0e 53      jne  0x53
  51:  03 ea      add  r14, r10
  53:  16 0e      ret  r14
```

Four independent tests, each adding 1 to `r14`, and `main` wants 4. Every one
is a short XOR chain against constants that are all sitting right there:

```
byte 3:  b ^ 0x37             == 0xe9   ->  0xde
byte 2:  b                    == 0xad   ->  0xad
byte 1:  b ^ 0x90 ^ 0x0f ^ 0x37 == 0x16 ->  0xbe
byte 0:  b ^ 0x13 ^ 0x37      == 0xcb   ->  0xef
```

`0xde 0xad 0xbe 0xef`. As an unsigned int that is 3735928559.

## the leak

`r14` is returned as-is, and `main` only compares it against 4. So the program
hands you a per-byte oracle for free: get one byte right and the return value
goes from 0 to 1. That is 4 * 256 probes to recover the password without
reading a single instruction of bytecode, and it is what `solve.brute()` does
as a cross-check on the hand derivation.

```
$ python3 solve.py
password: 3735928559 (0xdeadbeef)   vm() returns 4
```

## verification

`verify.py` calls the real `fcn.00400837` on the real bytecode under Unicorn,
with the context built the way `main` builds it, and diffs it against the
python reimplementation in `solve.py`:

```
$ python3 verify.py ./uck
 3735928559 (0xdeadbeef)  binary=4  solve.vm=4  -> Well done :-D
 3735928558 (0xdeadbeee)  binary=3  solve.vm=3  -> And... you failed !
          0 (0x00000000)  binary=0  solve.vm=0  -> And... you failed !
 1094861636 (0x41424344)  binary=0  solve.vm=0  -> And... you failed !

4/4 agree with the reimplementation
```

Note the second line: one byte wrong, three points. The oracle again.
