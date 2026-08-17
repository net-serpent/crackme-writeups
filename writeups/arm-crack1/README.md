# arm_crack1

blankwall, imported from crackmes.de. ARM EABI5, Thumb, dynamically linked,
stripped, difficulty 1.0. <https://crackmes.one/crackme/5ab77f5a33c5d40ad448c52b>

The bundled README asks for the flag "without patching or modification to the
binary", and says it was tested on an ARMv7 VM.

Flag: **`this_is_flag`**

## strings first

```
`TU_KU_KRXMS
STALE CONNECTION
DEBUGGING... Bye
WELCOME TO ARM CRACK ME LEVEL 1 or MAYBE IT WAS 2????? GOOD LUCK
 NO PATCHING OR MODIFYING WHATSOEVER
YOU Sol... OOOPS YOU DIDNT
yes FAIL
WAY TO GO SOLVED IT!
```

That first one is 12 bytes at `0x8a70` and is the flag under a shift. The rest
of the work is finding the shift.

## what main does

```c
char *s = (char *)0x8a70;                 /* the 12 encrypted bytes */
char *B = malloc(12), *C = malloc(12);
guard();                                  /* ptrace + alarm, see below */
char *D = malloc(12), *E = malloc(12);
memcpy(D, s, 12);
memcpy(B, s, 12);
guard_alarm();
fgets(E, 13, stdin);
if (strlen_ish(E) != 12) exit(1);
if (cmp(D, E) == 1) { printf("YOU Sol... OOOPS YOU DIDNT"); system("yes FAIL"); }
for (i = 0; i <= 11; i++) D[i] = (unsigned char)transform(D[i], 12, 12, 12);
memcpy(C, E, 12);
if (final(B, C, s, D) == 1) puts("WAY TO GO SOLVED IT!");
```

Note the middle branch: `cmp(D, E)` at that point compares your input against
the *raw* `.rodata` bytes, before the transform runs. Type the string you found
with `strings` and you get `yes FAIL` spawned at you. A trap aimed at exactly
the person who skips to the end.

## the transform (fcn.0000877c)

138 bytes, and this is the whole crackme. Called as `transform(byte, 12, 12, 12)`:

```asm
0x877c  ...
0x878a  mov.w r3, 0x34         ; stored to [r7+0x1c], never read again
0x8790  ldr   r3, [r7, 0xc]    ; a
0x8792  cmp   r3, 0xa
0x8794  ble   0x87a2
0x8796  ldr   r3, [r7, 0xc]
0x8798  str   r3, [r7, 4]      ; c = a          <- the only line that matters
0x879a  mov.w r3, 0x16         ; dead
...
0x87ac  ldr   r3, [r7, 4]
0x87ae  cmp   r3, 0x41
0x87b2  eor.w r3, r2, r3       ; a = b ^ c      -> dead, a is never read again
...
0x87d4  sub.w r3, r3, 0x12     ; a -= 0x12      -> dead
0x87dc  asr.w r3, r3, 2        ; d = c >> 2     -> dead
0x87e4  adds  r2, r2, r3       ; [r7+0x14] = a+b+c+d  -> dead
0x87f4  add.w r3, r3, 0x14     ; return c + 0x14
```

Six separate arithmetic results land in stack slots that nothing ever loads
again. The only value that reaches the return is `c`, which for any byte above
10 is the input byte itself. So the entire function is:

```c
return byte + 0x14;
```

`0x60 0x54 0x55 0x5f 0x4b 0x55 0x5f 0x4b 0x52 0x58 0x4d 0x53` plus 20 each is
`this_is_flag`.

## the comparison, which is also mostly theatre

`fcn.000086a8` is a strcmp that returns numbers picked to be awkward: 1 if both
strings ended together, -1 or -2 if only one did, 9 on any mismatch, and 1 once
it has matched past index 10.

`fcn.00008874(B, C, s, D)` then does:

```c
P = memcpy(B, D, 12);      /* the transformed flag */
x = cmp(P, C);             /* transformed vs your input */
y = cmp(s, D);             /* raw vs transformed -> differ at index 0 -> 9 */
while (x <= 7) x += cmp(P, C);
return y - x;
```

and main wants 1. With the right input `cmp(P, C)` is 1, so the loop runs until
`x` reaches 8, and `9 - 8 = 1`. With a wrong one `cmp` is 9 straight away, the
loop never runs, and `9 - 9 = 0`. A convoluted way to write `strcmp() == 0`.

## anti-debug

Two, both toothless:

- `fcn.00008650`: `ptrace(PTRACE_TRACEME, 0, 1, 0) < 0` prints `DEBUGGING... Bye` and exits 10
- `fcn.0000862c`: `signal(SIGALRM, 0x8611)` and `alarm(50)`, so you have 50 seconds before the handler fires. `STALE CONNECTION` is presumably what it prints.

## verification

This is the first ARM target here, so `tools/ucelf.py` grew a second
architecture: Unicorn in Thumb mode, AAPCS arguments in r0..r3, and the return
address taken from `lr` instead of the stack.

One ARM-specific gotcha cost me a while. Writing `pc` from inside a
`UC_HOOK_CODE` callback does not reliably break out of an already translated
block: the first stubbed call returned fine, the second ran the real PLT entry,
loaded an unrelocated GOT slot and jumped to 0. The fix is to have the stub
record the resume address, call `emu_stop()`, and let `call()` restart
emulation there, which is what the ARM path does now.

```
$ python3 verify.py Arm_crackme/arm_crack1
this_is_flag   exit=None  rv=1  WAY TO GO SOLVED IT!
`TU_KU_KRXMS   exit=None  rv=0  YOU Sol... OOOPS YOU DIDNT | <system 'yes FAIL'>
hello_world!   exit=None  rv=0
```

Second line is the trap firing, exactly as advertised.
