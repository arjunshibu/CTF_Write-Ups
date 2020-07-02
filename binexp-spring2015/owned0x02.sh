# disasssemble main
# set breakpoint at 0x804844e   cmp eax, DWORD PTR [ebp-0xc]
# gef➤  x/d $ebp-0xc
# 0xffffcfac:     338724
echo 338724 | ./crackme0x02
