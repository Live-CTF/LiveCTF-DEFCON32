#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io = process("./challenge")
io.sendline(b"5")
io.recvuntil(b"> ")
io.recvuntil(b"{")
buf = "{"+io.recvuntil(b"}").decode()
import json
print(buf)
buf = json.loads(buf)
from math import gcd, lcm
n = buf['n']
ctxt = buf['ctxt']
h = buf['hash']
n_sq = n * n
jj = {"hash":7738785012868993393085636460421496497382174193404728092925335783150778459348, "ctxt": pow(ctxt, 566079389444366126765319561333928769, n_sq)}
j = json.dumps(jj)
io.sendline(f"4 {j}".encode())
# msg = {'hash': h, 'ctxt': ctxt, 'n': n}
# print(json.dumps(msg))
io.recvuntil(b">")
print(io.recvall(timeout=0.5).strip().decode())
# io.interactive()
