# 1337_ARM

gtksor, 2011, imported from crackmes.de. ARM EABI4, statically linked, **not**
stripped, difficulty 2.0. <https://crackmes.one/crackme/5ab77f5733c5d40ad448c380>

Password: `ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`, passed as argv[1].

```bash
./1337ARM.bin 'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_'; echo $?
1337
```

## the trick is that there is no output

572KB of statically linked glibc around a `main` of 456 bytes. Grepping the
strings gets you nothing but libc's own diagnostics: no prompt, no "well done",
nothing. The program never prints. The entire result is its **exit code**, and
the name of the crackme is the answer you are looking for.

Symbols are intact, so `main` is right there at `0x8290`.

## main

```c
if (argc <= 1) return -1;

char **v = xmalloc(0x20);
for (i = 0; i != 8; i++) {
    v[i] = xmalloc(0x20);
    memset(v[i], '\n', 0x20);
}
v[8] = NULL;

for (i = 0, j = 0x41; i != 0x1f; i++, j++)
    v[3][i] = (char)j;
v[3][0x1f] = 0;

for (i = 0; argv[1][i]; i++)
    if (argv[1][i] != v[3][i]) return -1;

return 0x539;
```

Eight buffers get allocated and filled with newlines, and seven of them are
never touched again. Only `v[3]` matters, and it is filled with 31 consecutive
bytes starting at `'A'`:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
```

The tail past `Z` is just where ASCII goes next, which is what makes it look
more interesting than it is.

`0x539` at the literal pool at `0x8458` is 1337.

## the bug

Look at the loop bound: it iterates while `argv[1][i]` is non-zero, so it stops
at *your* string's NUL, not at the target's. Any prefix is accepted:

```
'ABCDE'                             exit=1337   accepted
'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_'   exit=1337   accepted
'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_x'  exit=-1     rejected
```

A single `A` is enough, and so is an empty argument. `solve.accepted()` models
that rather than pretending the check is tight.

## verification

`verify.py` calls the real `main` under Unicorn with `argc`/`argv` built in
emulated memory. This one is plain ARM rather than Thumb, so the harness gets
`thumb=False`; only `xmalloc` and `memset` are stubbed, the rest of `main` runs
as compiled.

```
$ python3 verify.py ./1337ARM.bin
'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'   exit=1337   accepted
'ABCDE'                              exit=1337   accepted
'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_x'  exit=-1     rejected
'ABCE'                               exit=-1     rejected
'hello'                              exit=-1     rejected

5/5 match solve.accepted
```

Rated 2.0, and most of that rating is the 572KB of statically linked libc you
have to look past to find a `main` that does nothing clever at all.
