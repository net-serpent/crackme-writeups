# x or and add

ray33ee, 2026, C/C++, x86-64, Windows PE. Difficulty 3.0, quality 4.3.
<https://crackmes.one/crackme/6a81d143184836c0dbe7d7e1>

> Find a passing name/password pair, then generate a keygen. Bonus points if you
> figure out the true extent of the keyspace and implement this in your keygen.

Example pair, any name works: **`adjacent` / `Et6emO57F2v3`**.

```
Name: adjacent
Password: Et6emO57F2v3
yes
```

## the shape of it

Stripped-to-external-PDB mingw binary. The prompts are the only strings that
matter: `Name: `, `%30s`, `Password: `, `%12s`, and then `yes` or `no`. main is
at `fcn.1400017b4` (the CRT startup hands it argc/argv the usual way). It reads a
name and a password, runs one hash and one comparison, and prints the verdict.

Everything hinges on three functions.

## the hash: name to a bucket

`fcn.140001688` walks the name and keeps a running value mod 400:

```c
int h = 0;
for (char *p = name; *p; p++)
    h = (h + (signed char)*p) % 400;   // the imul/sar dance is /400 signed
return h;
```

The `imul 0x51eb851f` / `shr 32` / `sar 7` is just the compiler's way of dividing
by 400 to take the remainder. So the name collapses to `H = sum(bytes) mod 400`,
and that is the *entire* influence the name has. Two names with the same byte sum
are interchangeable.

## the table lookup

main then pulls three bytes out of a table at `0x140013040`, indexed by the
bucket:

```c
E0 = TABLE[3*H + 0] & 0xff;
E1 = TABLE[3*H + 1] & 0xff;
E2 = TABLE[3*H + 2] & 0xff;
```

The table is a `uint32_t[1200]` but only the low byte of each entry is ever used.
I lifted it straight out of `.rdata` into `table.txt` so the keygen doesn't need
the binary around.

## the check: xor, add, xor, per character

`fcn.1400016f1(password, expected)` is where the name is "x or and add". First it
bails unless `strlen(password) == 12` (it compares against the reference string
`Cr4ckM35D0t1`, which is 12 long). Then, for each position i:

```c
r = ((password[i] ^ E0) + E1) ^ E2;
if (r != "Cr4ckM35D0t1"[i]) return 1;   // reject
```

The three constants don't depend on i, so every password byte is an independent
little equation, and it inverts cleanly:

```
pw[i] = (((REF[i] ^ E2) - E1) ^ E0) & 0xff
```

The only way a bucket can fail to have a byte solution is if `REF[i]^E2 < E1` for
some i (the intermediate would go negative). In this particular table that never
happens, and better still, every one of the 400 buckets produces a fully
printable 12-char password. `solve.py` keeps the negative guard anyway so it
stays honest about the arithmetic.

## the keyspace bonus

Here is the answer to the "true extent of the keyspace" question. The name only
ever reaches the check through `sum(name) mod 400`, so there are exactly **400
distinct passwords**, one per bucket. Names are an unbounded many-to-one label
sitting on top: infinitely many names, 400 keys. Every name is valid, and its
password is a pure function of its byte sum. A keygen doesn't need to search
anything, it reads three table bytes and inverts three operations.

```
python3 solve.py "your name here"
```

## verification

`verify.py` runs the real main under Unicorn and feeds it a name/password through
a stubbed `scanf`, then reads back whatever it tries to `printf`. If it prints
`yes`, the pair passed the binary's own hash and comparison, not my description
of them. `strlen`, the startup init, and stdio are stubbed; the hash, the table
lookup and the xor/add/xor loop all run as compiled.

```
$ python3 verify.py
name='adjacent'     pw='Et6emO57F2v3' -> 'Name: Password: yes'  OK
name='ray33ee'      pw="Wf(woQ')X$h%" -> 'Name: Password: yes'  OK
name='amorous'      pw='Gv4goM75D0t1' -> 'Name: Password: yes'  OK
name='Claude'       pw='O~<ogE?=L8|9' -> 'Name: Password: yes'  OK
name='net-serpent'  pw='O~8owQ?9H<x=' -> 'Name: Password: yes'  OK

negative control (bad password)  -> 'Name: Password: no'  OK
```

This was the first Windows x64 target here whose check actually calls back into
the binary during emulation, and it flushed out two bugs in the harness'
MS ABI path: the entry `rsp` wasn't left at `8 mod 16` the way a real call leaves
it (so a callee homed its arguments onto the return-address slot and returned
into its own argument), and the import-stub cleanup was popping stack args on
x64, where arguments come in registers and nothing is cleaned. Both are fixed in
`tools/ucload.py`; the whole `writeups/` set still verifies.
