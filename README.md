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

### how I work on these

I don't run the samples. They're random executables off the internet, and half
of them target platforms this machine isn't anyway. So: static analysis in
radare2, and when I need to actually execute something, it goes through Unicorn
with the libc/libstdc++ imports replaced by python stubs. x86, x86-64 and ARM
(both Thumb and not) all go through the same harness. `tools/ucelf.py` is
the harness that does the mapping and stubbing; each writeup's `verify.py` adds
whatever stubs that particular binary needs and calls the check function
directly.

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
