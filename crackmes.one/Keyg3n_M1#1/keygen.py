#!/usr/bin/env python3
# Author : 0xsegf
# https://github.com/arjunshibu
# https://www.hackthebox.eu/home/users/profile/201892
from random import sample
from sys import argv, exit

if len(argv) < 2:
	print(f"Usage: python3 {argv[0]} <number of keys>")
	exit(-1)
def gen_key(count):
	for i in range(count):
		key = ''
		randlist = sample(range(100, 123), 10)
		for asc in randlist:
			key += chr(asc)
		print(key)
gen_key(int(argv[1]))