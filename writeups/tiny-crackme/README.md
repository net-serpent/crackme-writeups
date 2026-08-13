# tiny_crackme

yanisto, 2016 or earlier, imported from crackmes.de. Linux ia32, difficulty 3.0.
<https://crackmes.one/crackme/5ab77f5833c5d40ad448c3ed>

769 bytes total, hand written asm, no libc, no sections worth the name. The
password is 4 bytes: **`b00m`**.

## the file

`file` gives up on it:

```
ELF 32-bit LSB executable, Intel 80386, statically linked, corrupted section
header size
```

which is the point. It is one of those minimal ELFs where the headers overlap
each other: `e_phentsize` is 0, `e_shoff` is 1, and the single program header
that matters says `PT_LOAD, offset 0, vaddr 0x200000, filesz 0x31b, flags RWX`.
The whole file is mapped once, writable and executable, and `e_entry` points
eight bytes into its own ELF header.

```asm
0x200008  mov  bl, 0x2a
0x20000a  jmp  0x200040
```

Everything past that is ciphertext until the code at 0x200040 decrypts it. 676
of the 795 bytes get rewritten in place before anything else happens.

## anti-disassembly

The decrypted code is full of five-byte `jmp +1`:

```asm
0x200040  e9 01 00 00 00     jmp 0x200046
0x200045  b0                 <- eaten as an opcode by any linear sweep
0x200046  e8 a5 02 00 00     call 0x2002f0
```

Same trick in the helper routines: `0x20029a` jumps to `0x2002a0`, which is the
real `write` wrapper (`mov ebx, eax; mov al, 4; int 0x80`), while a linear
disassembler starts at `0x20029f` and produces nonsense. objdump, radare2 and
capstone all fall for it in exactly the same place, which is a good reminder to
follow the branches instead of reading top to bottom.

## running it instead

The binary is freestanding and only makes four syscalls, so emulating it whole
is easier than reading it: `read`, `write`, `exit`, and one `ptrace`.

```asm
0x200072  mov eax, 0x1a          ; ptrace
0x200077  xor ecx, ecx           ; pid 0
0x20007b  mov edx, 1
0x200080  int 0x80               ; ptrace(PTRACE_TRACEME, 0, 1, 0)
0x200082  sub ebx, eax
0x200084  test eax, eax
0x200086  je  0x200099           ; 0 means nobody is tracing us
```

Standard PTRACE_TRACEME: it fails if a debugger already attached. Note it does
not just branch on the result, it also folds the return value into `ebx`, and
`ebx` gets pushed and re-checked *after* the password comparison. So patching
the branch alone still leaves you failing at the end.

## the check

```asm
0x20009c  push ebx               ; the anti-debug residue
0x20009d  mov  ecx, 0x200296
0x2000a2  mov  edx, 4
0x2000a7  call 0x2002aa          ; read(0, 0x200296, 4)
0x2000ac  call 0x2002c9          ; compute the expected value into ebx
0x2000b1  xor  ebx, [0x200296]
0x2000b7  je   0x2000cc          ; equal -> continue
...
0x2000cc  pop  ebx
0x2000cd  test ebx, ebx
0x2000cf  jne  wrong             ; and the ptrace residue must be zero
0x2000d1  print success
```

Exactly 4 bytes are read, and they have to equal whatever `0x2002c9` computes.
Since that routine also reads the input, the equation is self-referential.

Rather than unpick it, probe it. Feed the emulator a base input, change one
byte at a time and watch `ebx` at `0x2000b1`:

```
input[0] -> ebx byte 2      input[1] -> ebx byte 3
input[2] -> ebx byte 0      input[3] -> ebx byte 1
```

Each input byte drives exactly one output byte, through a fixed permutation. So
`ebx == input` decomposes into

```
input[0] = F2(input[2])     input[2] = F0(input[0])
input[1] = F3(input[3])     input[3] = F1(input[1])
```

two independent 2-cycles. Tabulate the four functions with 4 * 256 emulator
runs, then close each cycle by brute force over 256 values. No need to
understand the transform at all.

## the answer

256 four-byte strings pass. 32 of them are printable:

```
b(0e b*0g b,0a b.0c b00m b20o b40i b60k f(4e f*4g f,4a f.4c f04m f24o f44i f64k
r(@e r*@g r,@a r.@c r0@m r2@o r4@i r6@k v(De v*Dg v,Da v.Dc v0Dm v2Do v4Di v6Dk
```

`b00m` is obviously the one the author had in mind. `boom` is not accepted,
which is a nice little trap.

```
$ python3 verify.py ./tiny-crackme
b00m     expected=0x6d303062 (b'b00m')  -> Success !! Congratulations...
boom     expected=0x22303023 (b'#00"')  Wrong password, sorry...
AAAA     expected=0x1c1f0c71 (b'q\x0c\x1f\x1c')  Wrong password, sorry...

$ python3 verify.py ./tiny-crackme --search
256 accepted values, 32 of them printable
...
solve.py agrees: True
```

`verify.py` runs the whole binary from `e_entry` under Unicorn with `int 0x80`
handled in python, and `ptrace` returning 0, which is what an untraced process
gets. Nothing is patched to make it pass.

The solver lives in `verify.py` rather than `solve.py` for this one, because
the transform only exists after the binary has decrypted itself, so recovering
it needs the emulator anyway.
