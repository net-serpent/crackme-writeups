# drscm1

Dr.Spliff, Jan 2005, imported to crackmes.one from crackmes.de. Linux ia32,
difficulty 4.0. <https://crackmes.one/crackme/5ab77f5733c5d40ad448c306>

The README that ships with it is unusually honest, and worth reading before the
binary:

> Your goals for this crackme are to patch the application so that it thinks
> any key you enter is valid.
>
> It is trivially easy create a 'keygen' for this, i spent all of 20 minutes
> writing that part! [...] So dont bother - lamerPoints++ :)
>
> Tips: your looking for 56 bytes of position independant fairy dust :)

He is right on both counts: the serial is a byte sum, and the interesting part
is that the check does not exist anywhere in the file.

## where the check isn't

`main` reads a name and a serial, then does something you do not usually see in
a 4KB binary:

```c
buf = malloc(size);                       /* size = byte at 0x8049a58 = 56 */
memcpy(buf, (void *)0x8049a20, size);     /* rep movsb from .data */
for (i = 0; i < size; i += 8)
    decrypt(0x8049a5c, buf + i);          /* fcn.080485af, 8 bytes at a time */
mprotect(buf, size, 0);
((void (*)(void *, void *, void *))buf)(pair, 0x80484fc, 0x804855b);
```

So the payload is 56 encrypted bytes in `.data`, decrypted at runtime into a
malloc'd buffer and called with three arguments: the `{char *name; int serial;}`
pair and two callbacks. Static analysis of the binary will never show you the
comparison, because it is not there.

## the cipher

`fcn.080485af` is 120 bytes and gives itself away in the first instruction:

```asm
mov  esi, 0xc6ef3720        ; delta * 32
...
mov  dword [var_10h], 0x1f  ; 32 rounds
loop:
mov  edx, ecx
shl  edx, 4
add  edx, [k2]
lea  eax, [esi + ecx]
xor  edx, eax
mov  eax, ecx
shr  eax, 5
add  eax, [k3]
xor  edx, eax
sub  ebx, edx               ; v1 -= ...
...                         ; same shape again for v0, with k0/k1
add  esi, 0x61c88647        ; sum -= 0x9e3779b9
```

XTEA decryption, 32 rounds, `delta = 0x9E3779B9`. One simplification against
the real thing: stock XTEA picks the key word with `key[sum & 3]` and
`key[(sum >> 11) & 3]`, this one has the indices nailed down, k2/k3 on one half
and k0/k1 on the other. The key is the 16 bytes at `0x8049a5c`, sitting right
next to the ciphertext:

```
k = 16d30875 000e03d1 00962be5 001e458f
```

Only the decryption direction exists in the binary, which matters later: to
re-encrypt anything you have to write the other half yourself, and walk the sum
values back in the opposite order.

## the fairy dust

Decrypt the 56 bytes and they disassemble cleanly:

```asm
  00: push  ebp
  01: mov   ebp, esp
  03: push  esi
  04: sub   esp, 4
  07: mov   esi, [ebp + 8]        ; the {name, serial} pair
  0a: mov   ecx, 0
  0f: mov   edx, [esi]            ; name
  11: cmp   byte [edx], 0
  14: je    0x21
  16: movsx eax, byte [edx]
  19: add   ecx, eax              ; sum += (signed char)*p
  1b: inc   edx
  1c: cmp   byte [edx], 0
  1f: jne   0x16
  21: cmp   ecx, [esi + 4]        ; sum == serial?
  24: jne   0x2f
  26: sub   esp, 0xc
  29: push  esi
  2a: call  [ebp + 0xc]           ; ok(pair)
  2d: nop; nop
  2f: sub   esp, 0xc
  32: push  esi
  33: call  [ebp + 0x10]          ; bad(pair)
  36: nop; nop
```

`serial = sum of the name's bytes`, letter for letter what the README says.

Note the shape of the tail: after calling `ok` it falls straight through into
`bad`. The only reason you do not see both messages is that `ok` ends in
`mprotect`, `free` and `exit`, so it never comes back. Two nops sitting where a
`jmp` should be suggests that was on purpose, but it is a landmine either way.

```
$ python3 solve.py Dr.Spliff neshizoid
Dr.Spliff    -> 840
neshizoid    -> 973
```

## the patch he actually asked for

Patching the comparison in the file is not possible directly: those bytes are
ciphertext, and flipping any of them turns the whole 8-byte block into garbage
that will be executed. What you can do, once the key is in hand, is patch the
*plaintext* and re-encrypt it, which is what `solve.patch()` does. Nop out the
`jne` at offset 0x24 and the `ok` call stops being conditional:

```
75 09    jne 0x2f     ->    90 90    nop; nop
```

Re-encrypt the 56 bytes with the same key, write them back over `0x8049a20`,
and the binary accepts anything while still decrypting to something runnable.
That, and not the keygen, is the answer to the crackme as posed.

```bash
python3 solve.py --patch drscm1/drscm1 drscm1-patched
```

## verification

`verify.py` runs the real `main` in Unicorn with libc stubbed, so the binary
does its own XTEA pass and calls the decrypted buffer for real. It then diffs
the payload the binary produced in memory against `solve.plaintext()`, checks
the keygen against three names, and runs a freshly patched binary with a junk
serial:

```
$ python3 verify.py drscm1/drscm1
payload decrypted by the binary vs by solve.py:
  match   55 89 e5 56 83 ec 04 8b 75 08 b9 00 00 00 00 8b...

name / serial pairs:
  Dr.Spliff     840 -> Congrats (ok)
  Dr.Spliff     841 -> Sorry (ok)
  neshizoid     973 -> Congrats (ok)
  neshizoid     974 -> Sorry (ok)
  a              97 -> Congrats (ok)
  a              98 -> Sorry (ok)

patched binary, junk serial -> Congrats (ok)
```

The 2005 build notes warn that it needs glibc 2.3 and will misbehave on
anything older. Under emulation none of that matters, since libc is a handful
of python functions.
