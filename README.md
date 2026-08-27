# crackme-writeups

Notes from working through stuff off [crackmes.one](https://crackmes.one).

Each folder has the reconstructed algorithm, the answer, and a script that
checks the answer against the binary rather than against my own reading of it.

| crackme | author | | solved |
|---|---|---|---|
| [lincrackme3](writeups/lincrackme3) | adrianbn | linux x86-64, 2010 | keygen, `6067-9888-9347-1020` |
| [ELF - BCeption](writeups/bception) | Yir | linux x86-64, bytecode vm | `3735928559` |
| [crackme_1_by_huskyhusky](writeups/huskyhusky) | huskyhusky | linux x86-64, vm | keygen, weighted-sum checksum |
| [tiny_crackme](writeups/tiny-crackme) | yanisto | linux x86, 769 bytes | `b00m` |
| [drscm1](writeups/drscm1) | Dr.Spliff | linux x86, 2005 | keygen + re-encrypted patch |
| [arm_crack1](writeups/arm-crack1) | blankwall | linux arm, thumb | `this_is_flag` |
| [1337_ARM](writeups/1337-arm) | gtksor, 2011 | linux arm | `ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` |
| [ZED-Crackme](writeups/zed) | zed-zahir, 2020 | linux x86-64, upx | `C(uiICD@CADDEBNEEDD` |
| [KataVM Level 1](writeups/katavm) | Towel, 2021 | linux x86-64, vm | `xNVa2_N07_t3aAlg` |
| [what_is_my_password](writeups/what-is-my-password) | br0ken, 2009 | **windows** x86 | `95718t00w` |
| [learn_the_first_few_tricks](writeups/first-tricks) | deibiz_xxl, 2005 | **windows** x86 | `[DEIBIZ]` + name patch |
| [recoded_keygenme_1](writeups/recoded-keygenme) | recoded | windows x86, asm | keygen |
| [find the secret text](writeups/find-the-secret) | devoney | windows x86, self-patching | `[_Crack_]`, secret `greed` |
| [Simple Crackme](writeups/simple-x64) | raxer, 2020 | windows **x86-64** | `BXXGYYYBGIBXX` |

### how I work on these

I don't run the samples. They're random executables off the internet, and half
of them target platforms this machine isn't anyway. So: static analysis in
radare2, and when I need to actually execute something, it goes through Unicorn
with the libc/libstdc++ imports replaced by python stubs. `tools/ucload.py` is
the harness that maps the image and does the stubbing; it takes ELF and PE,
x86, x86-64 and ARM (Thumb or not). Each writeup's `verify.py` adds whatever
stubs that particular binary needs and calls the check function directly.

The binaries themselves aren't committed. To get one back:

```bash
python3 tools/fetch_crackme.py 5b23a35633c5d421d6f6d3e4 writeups/bception
```

The id is the hex blob in the crackmes.one URL.

### deps

```bash
brew install radare2
python3 -m venv .venv && .venv/bin/pip install unicorn pyelftools
```

`solve.py` is stdlib only, `verify.py` needs the venv.
