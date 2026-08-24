# KataVM -- Level 1

Towel (@0xTowel), 2021. Linux x86-64, PIE, stripped, difficulty 4.0, quality 6.0,
the best-rated thing in this repo.
<https://crackmes.one/crackme/605443e333c5d42c3d016f59>

> A small challenge with a virtualized function. [...] No fancy dynamic
> obfuscations or static analysis protections -- just the VM.

Input: **`xNVa2_N07_t3aAlg`**

This one took two attempts. The first died in a solver; what follows is what
actually worked.

## the shape

`main` is 74 bytes: call `fcn.000012d0`, print one of two strings depending on
the byte it returns. Watch the polarity, it is inverted from what you expect:

```asm
call fcn.000012d0
test al, al
jne  0x11ad        ; -> "[!] Invalid. Try harder."
                   ; fallthrough -> "[+] Correct!"
```

So **zero means accepted**. `fcn.000012d0` is 3910 bytes over 180 basic blocks:
`memcpy` drops 15130 bytes of bytecode from `0x3008` onto the stack, and a
dispatch loop walks it.

## the machine

Emulating the binary and watching the stubbed libc calls gives the layout for
free:

```
memcpy(dst, 0x3008, 0x3b1a)     dst = rsp + 0x30      the bytecode
read(0, rsp + 0x00, 4)          |
read(0, rsp + 0x04, 4)          | four reads, four bytes each
read(0, rsp + 0x00, 4)          |
read(0, rsp + 0x04, 4)          |
```

`read` writes **straight into the VM register file**. So the register file sits
at `rsp`, the input is 16 bytes, and it is consumed as two independent 8-byte
blocks. The "registers" turned out to be a ring of eight 32-bit slots, with two
opcodes whose whole job is rotating it.

Opcodes fall out of watching slot deltas per step:

| op | meaning | | op | meaning |
|---|---|---|---|---|
| `f6` | mov | | `7c` | shl imm8 |
| `4a` | add | | `b1` | shr imm8 |
| `aa` | sub | | `d5`, `1e` | rotate the ring |
| `8b` | xor | | `5d` | read 4 bytes |
| `ef` | no state change | | `c3` | compare slot with imm32 |

Hooking the `c3` handler prints the whole goal in one line:

```
cmp slot2 vs 0xfb987633     cmp slot3 vs 0xa2500488     (first half)
cmp slot2 vs 0x6ce7082d     cmp slot3 vs 0xc03a492f     (second half)
```

## the thing that made it tractable

Trace the VM with different inputs and the instruction sequence is **identical**,
step for step, all 2592 of them. Control flow never touches the data, so there
is exactly one path and no branch to reason about.

That means the whole computation is a straight-line program, and a straight-line
program can be recovered without ever decoding the bytecode. `derive.py` traces
a handful of random inputs and, for every step and every slot that changed,
looks for a single rule that explains it in **all** traces at once: `copy s`,
`add C`, `xor C`, `shl k`, `add slot`, and so on.

```
$ python3 derive.py
5 traces of 2592 steps
unexplained assignments: 4
  first: [(301, 0), (302, 1), (1448, 0), (1449, 1)]
```

Four unexplained assignments, and they are exactly the four `read` steps where
input enters. Everything else is recovered. A concrete interpreter of that
program reproduces the binary bit for bit.

What it recovered: 512 arithmetic ops per half, period 8 per half-round, so
64 half-rounds = **32 rounds**, with `((x<<4)+k) ^ ((x>>5)+k')` inside and a
running sum. TEA's shape, with delta `0xe09ffbb1` and keys `80b86e21/a268295d`
and `f171f22d/28a13c94`. Not stock TEA though: the `+sum` term uses the other
word, and in odd half-rounds the sum comes from a register rather than an
immediate. Trying 384 TEA and XTEA variants against a known input/output pair
found nothing, so the exact variant stays unnamed. It does not matter.

## inverting it

Handing all 512 ARX ops to z3 returns `unknown` after a minute, with or without
constraining the bytes to printable. ARX is precisely what bit-blasting is bad
at, and this is where the first attempt burned two hours doing nothing.

What works is not asking for much at a time:

- liveness analysis over the recovered program says only **3 or 4 slots are
  live** at a half-round boundary, and exactly 2 at the very start, which are
  the input words
- so walk backwards, and undo one segment at a time. Each segment is 16
  operations, which z3 answers instantly
- a segment can have more than one preimage, since a boundary carries more live
  slots than a couple of comparisons pin down. Keep the alternatives, check each
  by running forward to the targets, and backtrack when a branch dies

```
$ python3 solve.py --search
  half at step 301: xNVa2_N0
  half at step 1448: 7_t3aAlg
xNVa2_N07_t3aAlg
```

Fourteen seconds, against a minute of `unknown` for the same question asked all
at once.

## verification

`verify.py` runs the real `main` under Unicorn and prints the verdict the binary
itself prints. The VM executes its own bytecode; nothing is patched.

```
$ python3 verify.py
xNVa2_N07_t3aAlg   [+] Correct!
xNVa2_N07_t3aAlX   [!] Invalid. Try harder.
AAAAAAAAAAAAAAAA   [!] Invalid. Try harder.
```

## files

```
vmtrace.py   emulate the check function, trace the VM at bytecode level
derive.py    recover the straight-line program from traces
solve.py     liveness, backwards inversion with backtracking, the answer
verify.py    run the real main and read its verdict
```

`solve.py` needs z3 and the emulator for `--search`; plain `python3 solve.py`
just prints the recovered answer.

## notes

- the author says "just the VM" and means it: no anti-debug, no packing, no
  self-modifying code. The difficulty is entirely in the interpreter
- the polarity of the return value is the one cheap trap. Nonzero is failure
- recovering a program from traces only works because the VM is constant-time
  with respect to its input. A single data-dependent branch would have broken
  the whole approach, and would have been the obvious thing for the author to
  add
