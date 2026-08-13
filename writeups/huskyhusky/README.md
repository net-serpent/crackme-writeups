# crackme_1_by_huskyhusky

huskyhusky, 2016, imported from crackmes.de. Linux x86-64, difficulty 4.0,
the highest rated of anything I've done here.
<https://crackmes.one/crackme/5ab77f5633c5d40ad448c27b>

7KB, statically linked, stripped, no libc, three strings, and 1072 bytes of
`.text`. All of which is a VM, and the password check lives in its bytecode.

Working password (one of many): `}:"!!!!!!!!!!!!s~~~~~~~~`

## first look

```
$ r2 -qc 'iS; izq' crackme
1  0x000000b0  0x430  0x004000b0  -r-x  .text
2  0x000004e0 0x15f8  0x006004e0  -rw-  .data
0x600970  Please enter a password:
0x6009d8  Wrong!
0x6009f8  Correct! =)
```

Two functions. One is a decimal printer, the other is `entry0`, and `entry0`
is a fetch-decode-dispatch loop:

```asm
0x4000c0  mov   eax, dword [ecx*4 + 0x6008e8]   ; instruction word at pc
0x4000c8  movzx edx, ax                         ; low 16 bits  = operand
0x4000cb  shr   eax, 0x10                       ; high 16 bits = everything else
...
0x400183  and   eax, 7
          call  qword [rax*8 + 0x600868]        ; picks which register is "A"
0x4000d3  add   edx, edi                        ; operand += A
          test  eax, 0x10                       ; two levels of indirection,
          test  eax, 8                          ; each one an index into 0x6008e8
          movzx ebx, ah                         ; opcode
          inc   ecx                             ; pc++
0x40016f  shr   eax, 5
          and   eax, 7
          call  qword [rax*8 + 0x600868]        ; and again, for the destination
0x4000fc  jmp   qword [rbx*8 + 0x6004e0]        ; opcode handler
```

So `.data` is three tables and a program: a 113-entry opcode table at
`0x6004e0`, two 8-entry addressing-mode tables at `0x600868` and `0x6008a8`,
and from `0x6008e8` a flat dword-addressed memory holding both the bytecode
and its data. The strings live in that same space, which is why the program
refers to them by index: "Correct! =)" is word 68, "Wrong!" is word 60.

The mode tables are eight one-liners each, `mov edi, r8d` through
`mov edi, r15d`, so the VM's registers are literally the host's r8..r15 and
the mode bits choose which one an instruction operates on.

## finding the verdict

Emulating the whole binary is easy: it is static and talks to the kernel
directly, so `read`, `write` and `exit` are the only things to implement. From
there, tracing the VM pc turns up something useful immediately.

The pc trace is **identical** for every input of a given length. No data
dependent branching at all, so no timing or trace-length side channel. The
verdict is a single instruction near the top of the program:

```
idx  word      op  mode oper
  4  25200007  25  20   7      ; jump to 7 if A != 0
  5  02200044  02  20   68     ; ... else fall through: "Correct! =)"
  7  0220003c  02  20   60     ; "Wrong!"
```

with the handler for opcode 0x25 at `0x40036a`:

```asm
cmp edi, 0
je  next
mov ecx, edx          ; taken: pc = operand
```

`A == 0 means accepted`, and nothing else matters. The one thing to watch is
that `A` here is whichever host register the mode bits selected, not a memory
cell, so you have to read `edi` inside the handler and not at fetch time. I
lost a while diffing VM memory before noticing that.

## the check

Read `edi` at that instruction while varying one input byte at a time and the
whole thing falls out:

```
A = -75238 + sum(w[i] * password[i])
```

with the multipliers

```
3, 5, 7, 9, 11, 13, 15, 17, 19, 23, 25, 29, 31, 37, 41, 43, 47, 49, 53,
59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 121, 127, ...
```

which is the odd numbers with a primality filter that leaks: 9, 15, 25, 49 and
121 all get through. The bytecode generates them rather than storing them, so
there is no table to find in `.data`.

Accepted, then, is any string whose weighted sum is exactly **75238**. No
length check, no character set check beyond what you can type. It is a
checksum, so there is no single password, and the shortest string that can
reach 75238 with graphic ASCII is 22 characters.

## keygen

`solve.py` fills the heavy positions greedily, keeps a few hundred in reserve,
and closes the gap exactly with the weight-3 and weight-5 slots, since `3a + 5b`
covers every remainder from 8 up:

```
$ python3 solve.py 24 28 32
len 24: }:"!!!!!!!!!!!!s~~~~~~~~   sum=75238
len 28: {;!!!!!!"!!!!!!!!!!!!!!\~~~~   sum=75238
len 32: |;!!!!!!!!!!!!!!!!!!"!!!!!!!!;~~   sum=75238
```

## verification

`verify.py` boots the binary in Unicorn from `entry0`, types a password at the
`read` stub and collects the `write` output, which is as close to actually
running it as I am willing to get with a random 2016 ELF. It also re-derives
the multiplier table by probing, so the constants in `solve.py` are checked
against the binary rather than trusted:

```
$ python3 verify.py ./crackme
probed multipliers  [3, 5, 7, 9, 11, 13, 15, 17, 19, 23, 25, 29, 31, 37, 41, 43]
probed constant     -75238   (matches solve.py)

len 24: }:"!!!!!!!!!!!!s~~~~~~~~           A=  0  ->  'Correct! =)'
len 28: {;!!!!!!"!!!!!!!!!!!!!!\~~~~       A=  0  ->  'Correct! =)'
len 32: |;!!!!!!!!!!!!!!!!!!"!!!!!!!!;~~   A=  0  ->  'Correct! =)'
ctrl:   password                           A=-66415  ->  'Wrong!'
ctrl:   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   A=27202   ->  'Wrong!'
```

Rated 4.0 and it earns most of that from the VM itself. Once you can read the
dispatch loop, the password check is a weighted sum with a wrong answer for
what a prime is.
