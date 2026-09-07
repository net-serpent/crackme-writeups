# tools

Shared bits the writeups lean on. Three files:

- `ucload.py`, the emulation harness every `verify.py` imports
- `fetch_crackme.py`, grabs a sample back off crackmes.one
- `ci_check.py`, runs the self-contained solvers and checks their answers

## ucload.py

The point of the repo: instead of running an untrusted sample (which is usually
built for another OS anyway), I map its image under [Unicorn](https://www.unicorn-engine.org/),
stub out whatever it imports, and call one function directly with the arguments I
want. The check function runs as compiled; everything around it is python.

It takes ELF and PE, 32- and 64-bit, x86 and ARM, and picks the calling
convention from the image:

| image            | args land in                                    |
|------------------|-------------------------------------------------|
| x86 (32-bit)     | on the stack, cdecl                             |
| x86-64 ELF       | rdi, rsi, rdx, rcx, r8, r9 (SysV)               |
| x86-64 PE        | rcx, rdx, r8, r9 + 32 bytes of shadow (MS ABI)  |
| ARM (Thumb/plain)| r0..r3 (AAPCS)                                  |

### the shape of a verify script

```python
from ucload import Emu

emu = Emu('sample.exe', base=0)          # PE, so MS x64 ABI is picked for you

@emu.stub_import('strlen', argc=1)       # swap a library import for python
def _strlen(e):
    return len(e.read_cstr(e.arg(0)))

@emu.stub(0x1400019a7)                    # or a call at a fixed address
def _init(e):
    return 0

rv = emu.call(0x1400017b4, arg0, arg1)    # rax comes back, or 'abort:...'
```

### what you get

`parse_image(path)` on its own returns `{bits, arm, lo, hi, chunks, ...}` and, for
a PE, `pe`, `imports`, plus a section map, if you just want to read the layout or
pull bytes out of `.rdata`.

`Emu(path, base=BASE, thumb=True)` maps the image where it asks to sit, lays down
a stack, a heap, a `fs:0x28` canary in 64-bit mode, and pages for the return
trampoline and fake imports. `base=0` maps at the true virtual address, which is
what you want when you're copying addresses straight out of the disassembler.
`thumb` only matters for ARM.

The methods a stub or a driver actually uses:

- `call(addr, *args)` runs from `addr` until it returns, hands back `rax`/`r0`, or
  a string `'abort:...'` if it faulted or hit an `abort_at`. Always check for the
  string before using the result as a number.
- `arg(i)` reads the i-th argument, from inside a stub, dispatched by arch/ABI.
- `stub(addr)` / `stub_import(name, argc=0)` register a python replacement. The
  first hooks a fixed address in the image, the second writes a made-up address
  into the named IAT slot and hooks that (a PE `call [iat]` has nothing at a fixed
  address to hang a stub on otherwise). `argc` only pops stack args for 32-bit
  stdcall; x64 passes in registers and cleans nothing.
- `abort_at(addr, label)` stops the run with that label if execution reaches it,
  handy for "if it gets here, the check failed" branches.
- `alloc(bytes)` bumps a pointer in the heap and returns it. `reset_heap()` rewinds.
- `read_cstr`, `read_word`/`write_word` (native width), `read_u64`/`write_u64`.

Two `std::` conveniences at the bottom: `cxx_string(emu, b'...')` lays out a
libstdc++ `std::string`, and `strtol(text, base)` matches C's return triple for
when a stub has to stand in for it.

### the one gotcha

Writing `pc` from inside a code hook doesn't reliably break out of an
already-translated block on ARM. The stubs there record the resume address, stop,
and let `call()` restart at it; that's why the ARM path loops instead of running
straight through.

pip install unicorn pyelftools (or `-r ../requirements.txt`).

## fetch_crackme.py

The samples are never committed. To get one back, pass the hex id from the
crackmes.one URL and a destination:

```bash
python3 fetch_crackme.py 5b23a35633c5d421d6f6d3e4 ../writeups/bception
```

It prints the metadata, downloads the zip, and unpacks it with the site password
`crackmes.one`, leaving the sample non-executable so nothing runs it by accident.

## ci_check.py

Runs every solver that derives its answer without the sample and greps the output
for the known answer; the four that read the sample to lift constants get
structure-checked and skipped. This is what CI runs after byte-compiling
everything.

```bash
python3 ci_check.py -v
```

When you add a writeup, register its answer in `EXPECT` (or add it to `NEEDS_BIN`
if the solver can't run without the sample).
