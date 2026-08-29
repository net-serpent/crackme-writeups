# Simple Keygen

Yuri, 2019, Linux x86-64, PIE, not stripped, difficulty 1.5.
<https://crackmes.one/crackme/5c2acb8933c5d46a3882b8d4>

A 16-character serial, and any of a huge family works.

## the check

`checkSerial` at `0x1197`:

```c
if (strlen(s) != 16) return -1;
for (int i = 0; i < 16; i += 2)
    if (s[i] - s[i+1] != -1) return -1;   // s[i+1] == s[i] + 1
return 0;
```

Sixteen bytes, read as eight pairs, and each pair has to be two consecutive
characters: the second byte one more than the first. Nothing constrains which
characters, so `AB`, `BC`, `xy` all pass, and `ABBCCDDEEFFGGHHI` is one serial
built by stepping a seed.

## verification

`verify.py` calls `checkSerial` directly under Unicorn, stubbing only `strlen`.

```
$ python3 verify.py
ABBCCDDEEFFGGHHI   Good Serial
ABBCCDDEEFFGGHHZ   Bad Serial
short              Bad Serial
AAAAAAAAAAAAAAAA   Bad Serial
```
