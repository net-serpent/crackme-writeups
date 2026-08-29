# XORcist

S3c_Cult, 2025, Linux x86-64, PIE, stripped, difficulty 1.9.
"easy crackme with Control Flow Obfuscation, XOR encryption and anti-debugging"
<https://crackmes.one/crackme/684f47bd2b84be7ea774390e>

Password: **`ts_pmo_gng_icl`**

The author ships `xorcist.c` in the archive, but the password lives in the
binary, so none of the source has to be trusted.

## the check

`validate` at `0x1349` is three calls:

```c
char temp[16];
strcpy(temp, enc);        // enc = 14 bytes at 0x2023
decrypt(temp);            // fcn.1209: each byte ^= 0xA9
return strcmp(input, temp) == 0;
```

XOR with a single fixed key, so the 14 bytes at `0x2023` decode straight to the
password.

## the "obfuscation"

The three advertised tricks are all noise:

- **anti-debugging** is `isDebuggerPresent` (`fcn.1258`), the standard
  `/proc/self/status` TracerPid read. It gates the greeting, not the check.
- **control-flow obfuscation** is `main` calling `rand()`, `srand(time())` and
  a `useless_branch(rand() % 6969)` whose result is computed and dropped. There
  is also a `check_fn` function pointer in an `Agent` struct and an `ag.id != 0`
  guard where `id = rand() % 100 + 1` is never zero. None of it touches the
  comparison.
- **XOR encryption** is the single-byte `^ 0xA9` above.

## verification

`verify.py` calls `validate` under Unicorn with `strcpy`, `decrypt` and
`strcmp` running as compiled, so the blob and the `0xA9` key are read from the
binary rather than from the shipped source.

```
$ python3 verify.py
ts_pmo_gng_icl     accepted
ts_pmo_gng_iclx    rejected
password           rejected
```
