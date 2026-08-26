# crackme_2.0 find the secret text

devoney, imported from crackmes.de. Windows PE32, hand written assembler,
1.3KB, difficulty 2.0.
<https://crackmes.one/crackme/5ab77f5333c5d40ad448c109>

Password: **`[_Crack_]`**, and the secret text it reveals is **`greed`**.

## there is no comparison

Grep the whole binary and you will not find a `cmp` against the input, or a
stored password, or a checksum. What you find instead is this, at the end of
the dialog handler:

```asm
push dword [0x403021]        ; NULL
push dword [0x40301d]        ; 0x13 = 19 bytes
push 0x403009                ; the template in .data
push 0x401351                ; destination
push dword [0x4030c8]        ; GetCurrentProcess()
call WriteProcessMemory
nop                          ; <- 0x401350
nop                          ; <- 0x401351, and the 18 after it
```

The destination is the NOP sled immediately after the call. So the program
overwrites its own next 19 instructions with a buffer built from your input and
then falls straight into them. The buffer starts life as the string
`1234567890123456789`, which is a placeholder, not data.

## what your input does to it

The handler walks your characters and, per index, adds a constant and stores
the result into several fixed positions of that buffer:

```asm
cmp ebx, 0                   ; index 0
ja  next
sub cl, 0x5b
mov [0x40300a], cl
mov [0x40300f], cl
mov [0x403014], cl
mov [0x403016], cl
mov [0x403019], cl
mov [0x40301a], cl
mov [0x40301b], cl
add cl, 0x72
mov [0x40303a], cl           ; and one byte of the secret string too
```

Probing that under the emulator gives the whole map: nine input characters,
each owning a disjoint set of the 19 output bytes, always as
`out = in + constant`.

```
input[0] -> 1, 6, 11, 13, 16, 17, 18      input[5] -> 14
input[1] -> 0, 12                          input[6] -> 3
input[2] -> 2, 7                           input[7] -> 8
input[3] -> 4, 9                           input[8] -> 15
input[4] -> 5, 10
```

Every position is covered exactly once, so the map is invertible. Pick the code
you want and the password falls out.

## picking the code

The repetition tells you the shape before you know a single byte. Positions 1,
6, 11, 13, 16, 17 and 18 all come from `input[0]`, so those seven bytes are
equal; positions 0 and 12 are equal, 2 and 7 are equal, and so on. Lay that out:

```
offset  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18
value   B  A  C  G  D  E  A  C  H  D  E  A  B  A  F  I  A  A  A
```

Three identical bytes at the tail, a repeated `C ? D E A` pattern twice, and
`B A` at both the start and position 12. That is
`push 0 / push imm32 / push imm32 / push 0 / call rel32`, which is exactly
`MessageBoxA(0, text, caption, 0)`, and it fits in 19 bytes with nothing to
spare:

```
6a 00              push 0
68 3f 30 40 00     push 0x40303f     ; "Check at http://..."
68 25 30 40 00     push 0x403025     ; "The Secret Text is: ....."
6a 00              push 0
e8 32 00 00 00     call 0x401396     ; the MessageBoxA thunk
```

So `A = 0x00`, `B = 0x6a`, `C = 0x68`, `D = 0x30`, `E = 0x40`, `F = 0xe8`,
`G = 0x3f`, `H = 0x25`, `I = 0x32`, subtract each position's constant, and the
password is `[_Crack_]`.

## the second half of the trick

Look again at that snippet: after filling the code buffer, `input[0]` is
adjusted by `0x72` and stored at `0x40303a`. That address is inside
`The Secret Text is: 00000`, the string the shellcode is about to display. The
same character both assembles the call and fills in a letter of the answer, so
a wrong password does not simply fail, it prints a corrupted secret. Getting
the argument order of `MessageBoxA` backwards on my first attempt produced
`gree~` instead of `greed`, which is a nice way to be told you are one byte off.

## verification

`verify.py` calls the dialog handler at `0x4011a2`, lets `WriteProcessMemory`
genuinely rewrite the code in emulated memory, and then lets the patched bytes
run. The verdict is whatever reaches `MessageBoxA`.

```
$ python3 verify.py
[_Crack_]   6a 00 68 3f 30 40 00 68 25 30 40 00 6a 00 e8 32 00 00 00
            -> 'The Secret Text is: greed' / 'Check at http://members.lycos.nl/...'
[_Crack_x   6a 00 68 3f 30 40 00 68 25 30 40 00 6a 00 e8 4d 00 00 00
            -> nothing, the patched bytes are not a valid call
aaaaaaaaa   6c 06 86 35 1f 40 06 86 27 1f 40 06 6c 06 e6 36 06 06 06
            -> nothing, the patched bytes are not a valid call
```

One character wrong and the call displacement points into the middle of another
thunk, which is the failure mode this design gives you instead of a message box
saying no.
