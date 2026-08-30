# Keygen-Me

OTC, 2026, Linux x86-64, difficulty 2.8. "Simple keygen. Nothing too complex,
but there are some tricks along the way."
<https://crackmes.one/crackme/6a526a25234391ae74f63b19>

Flag: **`Cybersphere{Speed_2cacc3f62f300a06501df12be978b0a0857e768841ccc75d89986da061f0b55f}`**

The tricks are a UPX packer, a self-decrypting dropper, and a two-stage hash
check. All three come apart cleanly.

## trick one: UPX

```
$ strings task | grep UPX
UPX!
$ upx -d -o task.unpacked task
```

Stock UPX, header intact.

## trick two: the dropper

The unpacked binary is not the crackme, it is a loader. `main` decrypts a blob
and runs it from memory:

```c
srand(0x32);
for (i = 0; i < 0x58e8; i++)
    plain[i] = enc[0x4020 + i] ^ (rand() & 0xff);
fd = syscall(memfd_create, ...);
write(fd, plain, 0x58e8);
fexecve(fd, argv, envp);          // never touches disk
```

`memfd_create` + `fexecve` is the fileless-execution idiom: the real ELF only
ever exists in an anonymous fd. The key is glibc's `rand()` seeded with `0x32`,
so reproducing the stream means reimplementing glibc's TYPE_3 additive-feedback
`random()` (30-word state, 16807 multiplier init, `r[i] = r[i-31] + r[i-3]`).
`solve.py` does that and decrypts the inner ELF; its magic and four `PT_LOAD`
segments parse, which is the check that the RNG port is correct.

## trick three: the two questions

The inner ELF (OpenSSL, C++) asks for a name and a topic.

**Name.** `base64(name)` must equal `U3BlZWQ=`, which decodes to `Speed`. So the
name is **Speed**, and the `U3BlZWQ=` string in the binary is the giveaway.

**Topic.** `fcn.2968` builds the expected answer entirely from the name:

```
h1 = hex(MD5(name))               // fcn.27c0, algo "MD5"
h2 = xor42(h1)                    // fcn.2549, every byte ^= 0x42
topic == hex(SHA256(h2))          // fcn.27c0 "SHA256", compared to input
```

So the topic is not guessed, it is computed:

```
MD5("Speed")            = 44877c6aa8e93fa5a91c9361211464fb
that hex ^ 0x42         = 76 76 7a 75 75 21 74 23 ...
SHA256(...)             = 2cacc3f62f300a06501df12be978b0a0857e768841ccc75d89986da061f0b55f
```

## the flag

On success `main` prints `Cybersphere{` + name + `_` + topic + `}`, so the flag
is built from the two inputs you supplied:

```
Cybersphere{Speed_2cacc3f62f300a06501df12be978b0a0857e768841ccc75d89986da061f0b55f}
```

## verification

`verify.py` ties both computable stages back to the binaries rather than to the
source I read off the disassembly:

- it re-derives the inner ELF with the reimplemented glibc rand and confirms it
  parses (and matches the extracted copy)
- it calls `fcn.2549` under Unicorn on a test string and confirms the transform
  is `^ 0x42`

MD5 and SHA256 are the standard algorithms, so `hashlib` matches the OpenSSL the
binary links.

```
$ python3 verify.py
1. unpack: inner ELF magic b'\x7fELF'  valid=True  (22760 bytes)
   parses as ELF: 4 PT_LOAD segments
2. fcn.2549 xors with 0x42: True
flag:  Cybersphere{Speed_2cacc3f62f...}
```
