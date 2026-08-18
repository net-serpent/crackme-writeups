#!/usr/bin/env python3
"""1337_ARM by gtksor. The program prints nothing at all; the whole crackme is
its exit code, which has to come out as 1337.

main builds a table of eight 32-byte buffers, fills them with '\\n', then walks
one of them writing consecutive bytes starting at 'A':

    for (i = 0, j = 0x41; i != 0x1f; i++, j++)
        v[3][i] = j;
    v[3][0x1f] = 0;

and compares argv[1] against that, one byte at a time, stopping at argv[1]'s
own NUL. Match all the way and it returns the literal at 0x8458, which is
0x539.

    ./1337ARM.bin "$(python3 solve.py)"; echo $?      -> 1337
"""
import sys

FIRST, LENGTH, EXIT_OK = 0x41, 0x1F, 0x539


def password() -> str:
    return ''.join(chr(FIRST + i) for i in range(LENGTH))


def accepted(arg: str) -> bool:
    """The comparison stops at argv[1]'s NUL, so any prefix passes too."""
    full = password()
    return len(arg) <= len(full) and full.startswith(arg)


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '-c':
        a = sys.argv[2]
        print(f'{a!r} -> exit {EXIT_OK if accepted(a) else -1}')
        return
    print(password())


if __name__ == '__main__':
    main()
