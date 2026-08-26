# recoded_keygenme_1

recoded, imported from crackmes.de. Windows PE32, hand written assembler,
1.8KB, difficulty 2.0. <https://crackmes.one/crackme/5ab77f5333c5d40ad448c10c>

Goal is a keygen, and the success box says so: "Nice work. Now write a keygen
for it."

```
$ python3 solve.py neshizoid
name:   neshizoid
serial: BEFACE23-F510E91A-3C100C8A-DA375E6C
```

## the serial format

`fcn.004010a2` validates the 35 character serial one byte at a time:

```asm
cmp al, 0x30 / 0x39     ; 0-9
cmp al, 0x41 / 0x46     ; A-F
cmp al, 0x61 / 0x66     ; a-f
cmp al, 0x2d            ; or a dash, but only where
mov eax, ebx
inc eax
div ecx                 ; (index + 1) % 9 == 0
or  edx, edx
jne bad
mov byte [ebx + edi], dl   ; and the dash is overwritten with the NUL from edx
```

So four groups of eight hex digits joined by dashes, and the dashes are turned
into terminators in place, leaving four separate hex strings sitting in the
buffer at `0x40303f`, `0x403048`, `0x403051` and `0x40305a`.

## the four rounds

Write `S(m)` for

```
sum over the name's characters, skipping spaces, of  ror32((c & 0xff) * m, 19)
```

which is this loop, once per round:

```asm
mov al, byte [ecx + edi]
cmp al, 0x20
je  skip                  ; spaces do not contribute
and eax, 0xff
imul eax, dword [0x40308b]
ror eax, 0x13
sub ebx, eax
skip:
inc ecx
dec edx
jne loop
or  ebx, ebx
jne bad                   ; the group has to be exactly the sum
```

The multiplier changes each round, and that is where the design is:

| round | ebx starts as | multiplier |
|---|---|---|
| 0 | group 0 | group 1 |
| 1 | group 1 | group 2 |
| 2 | group 2 | group 3 |
| 3 | group 3 | `0x4012a2`, a constant |

Read forwards it looks circular: every group is defined in terms of the next
one. Read backwards it is not circular at all, because the last round has no
unknown on the right hand side:

```
g3 = S(0x4012a2)
g2 = S(g3)
g1 = S(g2)
g0 = S(g1)
```

Four lines, and that is the keygen. The name has to be at least 4 characters;
nothing else about it is constrained, spaces included.

## verification

`verify.py` calls the check routine at `0x4010ef` directly under Unicorn, with
`GetDlgItemTextA` feeding it a name and a serial and `MessageBoxA` catching the
verdict. The dialog never opens.

This is also where `tools/ucload.py` learned the last thing it needed for
Windows: PE calls go through `call [iat]`, so there is no fixed thunk address
to hook the way an ELF PLT gives you. The loader now parses the import
directory, points each named slot at an address of its own choosing, and hangs
the python stub there. Those stubs also have to pop their own arguments, since
win32 is stdcall and the callee cleans the stack.

```
$ python3 verify.py
neshizoid    BEFACE23-F510E91A-3C100C8A-DA375E6C  Nice work. Now write a keygen for it.
promix17     D75D6937-A7E63121-33B51099-0D0DD83C  Nice work. Now write a keygen for it.
abcd         DADCD869-704090CA-7E644B0D-95AA8C50  Nice work. Now write a keygen for it.
neshizoid    BEFACE23-F510E91A-3C100C8A-DA375E60  Invalid Credentials.   (one digit off)
```
