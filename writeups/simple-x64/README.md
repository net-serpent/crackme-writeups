# Simple Crackme

raxer, 2020, Windows PE32+ (x86-64) console, difficulty 2.0.
"Beginner friendly, no bytepatching."
<https://crackmes.one/crackme/5ed5b3c833c5d449d91ae6d0>

Password: **`BXXGYYYBGIBXX`**

## the whole program

`entry0` is 131 bytes and does everything itself. It prints a banner, reads a
line with `gets_s`, and checks 13 characters:

```asm
lea  rax, [rip - 7]        ; rax = 0x400418  (this very lea)
mov  rsi, rax
...
lea  r8, [0x400262]        ; an 8 byte table
loop:
  dl  = input[i]
  ecx = code[0x400418 + i]
  and ecx, 7
  cmp dl, table[ecx]
  jne fail
  inc rax
  cmp rax, 0xd             ; 13 characters
  jne loop
cmp byte [buf + 13], 0     ; and nothing after
```

So `password[i] = table[code[i] & 7]`, where `code` is the 13 bytes the `lea`
points at, starting with the `lea` instruction itself. The table is `BGOTHXIY`
sitting in `.rdata`.

The key material is the program's own machine code, which is what "no
bytepatching" is protecting: change any of those 13 instruction bytes and the
password changes with them, so you cannot patch your way past the check without
also invalidating the answer you would type.

```
code:  48 8d 05 f9 ff ff ff 48 89 c6 48 8d 0d
&7:     0  5  5  1  7  7  7  0  1  6  0  5  5
table[]: B  X  X  G  Y  Y  Y  B  G  I  B  X  X
```

`BXXGYYYBGIBXX`.

## verification

This is the first 64 bit PE in the repo, so `tools/ucload.py` learned the
windows x64 convention: arguments in `rcx`/`rdx`/`r8`/`r9`, plus 32 bytes of
shadow space above the return address that the callee may spill into. Same
`parse_image` path as any other PE, it just sets an `msabi` flag off the bitness.

`verify.py` runs the whole `entry0` and stubs the four CRT imports it touches
(`puts`, `gets_s`, `__acrt_iob_func`, `__stdio_common_vfprintf`).

```
$ python3 verify.py
BXXGYYYBGIBXX    Good job on decrypting the password!
BXXGYYYBGIBXXX   Don't think you have the slightest clue about debugging.
BXXGYYYBGIBXZ    Don't think you have the slightest clue about debugging.
hunter2          Don't think you have the slightest clue about debugging.
```
