# ZED-Crackme

zed-zahir, 2020-05-26, Linux x86-64, difficulty 2.0. "find the serial"
<https://crackmes.one/crackme/5ecd7cc133c5d449d91ae641>

Serial: **`C(uiICD@CADDEBNEEDD`**

The binary asks nicely on startup:

```
**      rules:       **
* do not bruteforce
* do not patch, find instead the serial.
```

Fine. Neither was needed.

## unpacking

```
$ file ZED-Crackme-x64.bin
ELF 64-bit LSB shared object, x86-64, statically linked, no section header
$ strings -a ZED-Crackme-x64.bin | grep UPX
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
```

Stock UPX with the header intact, so `upx -d` gives back a 13KB PIE with full
symbols:

```bash
upx -d -o ZED-unpacked.bin ZED-Crackme-x64.bin
```

## the decoys

The symbol table is the best part of this crackme:

```
sym.checkSerial  sym.cryptSerial  sym.gauss_eliminate  sym.swap_row
sym.generic_fizz_buzz  sym.obfuscation  sym.compare  sym.rot
```

Cross-reference every one of them:

| function | callers |
|---|---|
| `checkSerial` | none |
| `cryptSerial` | none |
| `obfuscation` | none |
| `gauss_eliminate` | only `cryptSerial`, which is dead |
| `swap_row` | only `gauss_eliminate` |
| `generic_fizz_buzz`, `compare` | only `obfuscation`, which is dead |
| `rot` | `main`, twice |

So a Gaussian elimination solver, a fizzbuzz and a qsort comparator all sit in
the binary with nothing reaching them. The only live helper is `rot`, called as
`rot(13, buf)` twice in a row on a stack string, which is the identity, and the
string it rotates ("This is a top secret text message!") is never used again.

Spend your time in those and you will have a long evening.

## the guards

Two, both in `main`, both cheap:

```asm
sidt   [rbp - 0x96]
movzx  eax, byte [rbp - 0x91]
cmp    al, 0xff
jne    ok                       ; else "VMware detected", exit(1)
```

The classic Red Pill: on VMware the IDT base lands high enough that the top
byte reads 0xff. And after the input is read:

```asm
call ptrace         ; ptrace(PTRACE_TRACEME, 0, 0, 0)
test rax, rax
jns  ok             ; else "This process is being debugged!!!", exit(1)
```

## the actual check

Nineteen bytes get assembled on the stack from three immediates:

```asm
movabs rax, 0x4145443332694841      ; "AHi23DEA"
movabs rdx, 0x464f434645454244      ; "DBEEFCOF"
mov    word [var_80h], 0x4546       ; "FE"
mov    byte [var_7eh], 0x45         ; "E"
```

which is `AHi23DEADBEEFCOFFEE`, and yes, that spells DEADBEEF COFFEE. Watch the
byte order on that third one: `0x4546` little-endian is `F`,`E` and not `E`,`F`.
I got it backwards first time round and produced a serial that was right except
for two transposed characters, which the emulator caught immediately.

Then, straight out of the disassembly:

```c
s[0] = M[0] ^ 2;
s[1] = M[3] - 10;
s[2] = M[2] + 12;
s[3] = M[2];
s[4] = M[1] + 1;
for (i = 5; i <= 18; i++) s[i] = M[i] - 1;
strcmp(s, input) == 0 ? "you succeed!!" : "try again";
```

The first five are shuffled and mangled individually, the remaining fourteen
just shift down by one. Result:

```
$ python3 solve.py
magic  AHi23DEADBEEFCOFFEE
serial C(uiICD@CADDEBNEEDD
```

## verification

`verify.py` runs the unpacked binary's real `main` under Unicorn and feeds the
candidate through the `scanf` stub. `ptrace` returns 0 and `sidt` gets whatever
Unicorn leaves in the IDTR, which is not 0xff, so both guards pass on their own
terms rather than being patched out.

`__ctype_b_loc` needs a real answer, since `rot` uses the ctype macros: the stub
builds a proper glibc flag table and hands back a pointer to it. Without that
the emulator jumps through an empty GOT slot into the ELF header.

```
$ python3 verify.py ./ZED-unpacked.bin
C(uiICD@CADDEBNEEDD    you succeed!!
AHi23DEADBEEFCOFFEE    try again
C(uiICD@CADDEBNEEDX    try again
```

Second line is worth keeping: the magic string itself is not the serial, only
its mangled form is.
