#!/usr/bin/env python3
"""Runs every self-contained solver and checks it still prints the answer it is
supposed to. This is what CI leans on: the sample binaries are never committed,
so verify.py can't run in CI, but most solve.py scripts derive the answer from
committed data (or pure math) and don't need the sample at all. Those we run for
real and grep the output.

The four that read the sample to pull constants out of it are listed in NEEDS_BIN.
CI skips running them, but they still have to have the usual three files and they
still get byte-compiled, so a syntax break or a missing file is caught anywhere.

    python3 tools/ci_check.py           # run it
    python3 tools/ci_check.py -v        # also print each solver's first line
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRITEUPS = ROOT / 'writeups'

# A stable substring each solver must print. For keygens that emit several pairs,
# it's the first deterministic serial; for the rest, the recovered answer.
EXPECT = {
    '1337-arm': r'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_',
    'bception': '0xdeadbeef',
    'drscm1': 'neshizoid    -> 973',
    'find-the-secret': '[_Crack_]',
    'first-tricks': '[DEIBIZ]',
    'huskyhusky': 'sum=75238',
    'katavm': 'xNVa2_N07_t3aAlg',
    'lincrackme3': '6067-9888-9347-1020',
    'recoded-keygenme': 'self-check: True',
    'simple-keygen': 'ABBCCDDEEFFGGHHI',
    'tiny-crackme': 'b00m',
    'what-is-my-password': '95718t00w',
    'xor-and-add': 'Et6emO57F2v3',
    'zed': 'C(uiICD@CADDEBNEEDD',
}

# Solvers that read the sample binary to lift constants out of it. Can't run
# without the sample, which isn't in the repo, so CI only structure-checks them.
NEEDS_BIN = {'arm-crack1', 'keygen-me', 'simple-x64', 'xorcist'}

TRIO = ('README.md', 'solve.py', 'verify.py')


def run_solver(name: str) -> tuple[bool, str]:
    d = WRITEUPS / name
    try:
        r = subprocess.run([sys.executable, 'solve.py'], cwd=d,
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return False, 'timed out'
    if r.returncode != 0:
        tail = (r.stderr.strip().splitlines() or [''])[-1]
        return False, f'exit {r.returncode}: {tail}'
    want = EXPECT[name]
    if want not in r.stdout:
        return False, f'output missing {want!r}'
    return True, r.stdout.strip().splitlines()[0]


def main() -> int:
    verbose = '-v' in sys.argv[1:]
    dirs = sorted(p.name for p in WRITEUPS.iterdir() if p.is_dir())

    problems = []
    passed = skipped = 0
    for name in dirs:
        missing = [f for f in TRIO if not (WRITEUPS / name / f).exists()]
        if missing:
            problems.append(f'{name}: missing {", ".join(missing)}')
            print(f'  FILES  {name}: missing {", ".join(missing)}')
            continue

        if name in NEEDS_BIN:
            print(f'  skip   {name}  (needs the sample binary)')
            skipped += 1
            continue

        if name not in EXPECT:
            problems.append(f'{name}: no expected answer registered in ci_check.py')
            print(f'  ????   {name}: not in EXPECT and not in NEEDS_BIN')
            continue

        ok, detail = run_solver(name)
        print(f'  {"ok    " if ok else "FAIL  "} {name}'
              + (f'  {detail}' if verbose or not ok else ''))
        if ok:
            passed += 1
        else:
            problems.append(f'{name}: {detail}')

    print(f'\n{passed} solvers ok, {skipped} skipped (sample needed), '
          f'{len(problems)} failed')
    if problems:
        print('\nproblems:')
        for p in problems:
            print(f'  - {p}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
