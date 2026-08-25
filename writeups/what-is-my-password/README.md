# what_is_my_password

br0ken, 2009, imported from crackmes.de. Windows PE32 console, MSVC with a
static CRT, difficulty 2.0.
<https://crackmes.one/crackme/5ab77f5333c5d40ad448c103>

> All you need to do is find my password. There are no rules! [...]
> Instructions to verify the pass is inside the cme.

Password: **`95718t00w`**

## what it does with your input

`main` prints a banner, reads a line, and checks the length the long way round:

```asm
repne scasb          ; strlen
not  ecx
add  ecx, 8
cmp  ecx, 0x12       ; len + 9 == 18, so exactly 9 characters
```

Then it loads five of those characters into registers and runs them through a
pile of `lea` and `sub`. It looks like obfuscation and it is not: every block
is one linear equation, and `lea` is just how the compiler writes multiplication
by small constants.

```asm
lea edi, [ebx + eax]        ; a + e
lea edi, [edi + edi*2]      ; *3
lea edi, [edi + edx*2]      ; + 2c
sub edi, esi                ; - b
sub edi, ecx                ; - d
cmp edi, 0x15b              ; == 347
```

Five of those, over `password[0..4]`:

```
3a -  b + 2c -  d + 3e = 347
6a - 2b -  c + 3d - 4e = 104
 a + 3b - 3c + 7d +  e = 450
2a +  b + 3c + 3d - 7e = 87
 a +  b +  c +  d +  e = 270
```

Five equations, five unknowns, one solution: `95718`.

The tail is checked separately and much more simply:

```asm
mov cl, [esp+0x16]   ; password[6]
xor cl, 0x6f
cmp cl, 0x5f         ; -> '0'

mov dl, [esp+7]      ; password[7], after four pops
mov al, [esp+6]      ; password[6]
xor dl, al           ; -> equal, so '0' again

movsx ecx, [esp+8]   ; password[8]
movsx eax, [esp+5]   ; password[5]
sub  edx, eax
cmp  edx, 3          ; difference 3
add  ecx, eax
cmp  ecx, 0xeb       ; sum 235   -> 'w' and 't'
```

Watch the four `pop` instructions in the middle of that: they shift `esp`, so
`[esp+7]` after them is `[esp+0x17]` before, which is `password[7]`. Read the
offsets without accounting for the pops and the last three conditions land on
the wrong characters.

Put together: `95718` + `t` + `0` + `0` + `w`.

## the free check

The success path prints:

```
The MD5 hash of the password should be 7eeeec6420a2a99b123f66b5c5231547
If it isn't, then you have come till here by patching me, which means
you don't have my correct password, hahaha :D
```

So the author shipped a checksum of his own answer, which makes this the one
crackme here that can be confirmed without touching the binary at all:

```
$ python3 solve.py
password: 95718t00w
md5     : 7eeeec6420a2a99b123f66b5c5231547
expected: 7eeeec6420a2a99b123f66b5c5231547   match
```

That is also the anti-patch measure working exactly as intended: patch the
jumps and you still get told the hash you cannot produce.

## verification

`verify.py` runs `main` under Unicorn through the new PE loader. The CRT is
linked statically, so the check reaches nothing in kernel32 at all: stubbing
four internal helpers (print a string, read a line, the failure path, the
pause at the end) is the entire runtime this needs.

```
$ python3 verify.py
95718t00w    Congrats, you have found my password!
95718t00x    You have failed!
password1    You have failed!
```
