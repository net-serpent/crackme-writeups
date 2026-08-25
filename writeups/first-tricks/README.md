# learn_the_first_few_tricks #1

deibiz_xxl, 2005, imported from crackmes.de. Windows PE32 console, MinGW,
difficulty 2.5. <https://crackmes.one/crackme/5ab77f5333c5d40ad448c11a>

The instructions set two goals: find the password without patching, then patch
the name the banner prints. Both below.

Password: **`[DEIBIZ]`**

## goal one

Two strings sit next to each other in `.rdata`:

```
0x402000  ZCDHAHY\
0x402009  XXXXXXXXXXXX
```

The first one is cross-referenced from a function MinGW kindly left a symbol
for, `createGoodBoy` at `0x401357`, all eight lines of it:

```asm
mov  dword [ebp-4], 0
loop:
cmp  dword [ebp-4], 7
jg   done
mov  edx, [ebp-4]
add  edx, 0x404060          ; the buffer it builds
mov  eax, [ebp-4]
add  eax, 0x402000          ; "ZCDHAHY\"
movzx eax, byte [eax]
inc  al                     ; +1, and that is the whole cipher
mov  [edx], al
```

`main` then `scanf`s into `0x404070`, calls `createGoodBoy`, and `strcmp`s the
two buffers. So the password is that string with one added to every byte:

```
Z C D H A H Y \      ->      [ D E I B I Z ]
```

which is the author's own handle in brackets. `\` is `0x5c`, so it becomes
`0x5d`, the closing bracket, which is a nice touch.

## goal two

The banner does `printf("Cracked By: %s (put your name here by patching).\n",
"XXXXXXXXXXXX")`. Twelve bytes of placeholder in `.rdata` at `0x402009`, and
nothing computes or checks them, so goal two is one write into the file:

```bash
python3 solve.py --patch LTFFT.exe LTFFT-patched.exe neshizoid
```

`solve.py` walks the section table itself to turn the virtual address into a
file offset, asserts the twelve `X` are still there, and pads the replacement
with NULs so the string stays terminated.

## verification

This is the repo's first Windows target, so `tools/ucload.py` (which used to be
`ucelf.py`) grew a PE branch: read `SizeOfImage` and the section table, map each
section at its virtual address, and everything downstream stays the same. No
import table is resolved, because the four functions this crackme needs from
msvcrt get python stubs anyway.

```
$ python3 verify.py
[DEIBIZ]     Well done, have you patched your name?
[DEIBIZ)     Bad... you should work harder.
password     Bad... you should work harder.

goal two: Cracked By: neshizoid (put your name here by patching).  (ok)
```

`createGoodBoy` and the `strcmp` run as compiled; only `printf`, `scanf`,
`strcmp`, `system` and the CRT init are stubbed.
