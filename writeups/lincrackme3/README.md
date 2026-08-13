# lincrackme3

adrianbn, 2010, imported to crackmes.one from crackmes.de. Linux, ships both a
32 and a 64 bit build; I worked on `lincrackme3-64`.
<https://crackmes.one/crackme/5ab77f6333c5d40ad448ca00>

The banner tells you the job:

> Key format: XXXX-YYYY-WWWW-ZZZZ with all numbers. [...] Keep an eye on
> antidebugging techniques, because thats the reason for this crackmes.

Which is fair warning, but the anti-debugging is the whole point and the key
check underneath it is four lines of arithmetic.

## input handling

`fcn.00400819(buf, 17)` is a hand rolled `getchar` loop:

- `-` is skipped and does not count
- anything outside `'0'..'9'` returns -1 straight away
- it stops at `\n`, at NUL, or once it has 16 digits, then drains the rest of the line

`main` requires the return value to be exactly 16, so the dashes are cosmetic:
`1234567890123456` is the same input as `1234-5678-9012-3456`.

## the anti-debugging

Two checks, and the second one is easy to walk past.

**A `.ctors` entry.** The section at `0x601e10` is the old GCC constructor
format, `{-1, 0x4007f1, 0}`, so `fcn.004007f1` runs before `main`:

```c
if (close(3) == 0) { puts("Debugger detected. Bye!"); exit(-1); }
```

If fd 3 is open you are probably running under something that left a descriptor
around. It fires before `main`, so a breakpoint on `main` is already too late.

**ptrace, reached through a jump into the middle of an instruction.** `main`
stashes `0x4007b4` in a local, then:

```asm
0x400a53   call 0x400a59          ; call the next instruction, to get rip
0x400a59   pop  rax               ; rax = 0x400a58
0x400a5a   add  rax, 0xbc
0x400a60   push rax
0x400a61   ret                    ; -> 0x400b14
0x400b14   mov  rbx, [rbp-0xf0]   ; 0x4007b4
0x400b1b   call rbx               ; ptrace(PTRACE_TRACEME, 0, 1, 0) < 0 -> exit
0x400b1d   jmp  0x400a63          ; land mid-instruction, the real loop lives here
```

`0x400a62` holds `e9`, so a linear disassembler eats the first byte of the
following instruction and produces garbage for the next screenful. Start
reading at `0x400a63` instead and it decodes cleanly. radare2 gets this wrong
until you seek there yourself.

## the check

Past all that, the loop is four accumulators over four groups of four digits:

```c
uint16_t s[4] = {0, 0, 0, 0};
for (int i = 0; i < 4; i++) {
    s[0] += key[i]      - '0';
    s[1] += key[i + 4]  - '0';
    s[2] += key[i + 8]  - '0';
    s[3] += key[i + 12] - '0';
}
```

and then, at `0x400b23`, five conditions in a row:

```asm
lea  ecx, [rdx + rax]      ; s0 + s1
lea  eax, [rdx + rax]      ; s2 + s3
add  eax, eax
cmp  ecx, eax              ; s0 + s1 == 2 * (s2 + s3)
jne  fail
cmp  ax, [rbp - 0xd6]      ; s1 > s2
jbe  fail
lea  eax, [rdx + rax]
and  eax, 1                ; (s0 + s3) even
jne  fail
cmp  word [rbp - 0xd2], 5  ; s0 > 5
jbe  fail
cmp  word [rbp - 0xd2], 0x18
ja   fail                  ; s0 <= 24
movzx eax, word [rbp - 0xd8]
and  eax, 1
test eax, eax
jne  win                   ; s3 odd
```

So the key only has to satisfy, on the four digit sums:

```
s0 + s1 == 2 * (s2 + s3)
s1 > s2
(s0 + s3) even
5 < s0 <= 24
s3 odd
```

The last two together force `s0` odd as well. The digits inside a group are
completely free, so each accepted `(s0, s1, s2, s3)` is really a family of keys.

Both result strings are stored XORed, decrypted a character at a time straight
into `putchar`: `^0xe9` for `Wrong key! I've seen monkeys smarter than you...`
and `^0xf9` for `Good! You got it, congratz. Have you tried to keygen me? Next
crackme soon ^_^`. Yes, I did.

## keygen

`solve.py` enumerates the accepted sum tuples and then picks random digits for
each group:

```
$ python3 solve.py
6067-9888-9347-1020   s=(19, 33, 23, 3)
9257-9499-8167-2120   s=(23, 31, 22, 5)
8407-8999-6000-1578   s=(19, 35, 6, 21)
...
```

## verification

`verify.py` runs the actual `main` in Unicorn with libc stubbed, types each key
through the `getchar` stub, and prints what comes back out of `putchar`.
`ptrace` returns 0 and `close` returns EBADF, so both anti-debug checks are
answered truthfully rather than patched away.

```
$ python3 verify.py ./lincrackme3-64
6067-9888-9347-1020  exit=-  Good! You got it, congratz. Have you tried to keygen
...
1111-1111-1111-1111  exit=1  Wrong key! I've seen monkeys smarter than you...

11/11 agree with solve.check()
```
