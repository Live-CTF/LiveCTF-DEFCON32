#!/usr/bin/env python3

from pwn import *
import json
import hashlib
#context.log_level = 'DEBUG'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

test = b'./submitter; "92'
test = b'./submitter  dt'
multiplier = 2211247615017055182677029540624262
multiplier = 8637685996160371807332146626748

io = remote(HOST, int(PORT))
io.sendlineafter(b'> ', b'5')
io.recvuntil(b'submitter')
io.recvline()
recv = io.recvline().decode().strip()
#print('recv', recv[-40:])
res = json.loads(recv)


c1 = res['ctxt']
n_sq = res['n'] ** 2
dictt = {'hash': int(hashlib.sha256(test).hexdigest(), 16), 'ctxt': pow(c1, multiplier, n_sq)}
# print(hex(res['n']))
# print(hex(res['hash']))
# print(hex(res['ctxt']))
io.sendlineafter(b'> ', b'4'+json.dumps(dictt).encode())
print(io.recvline())
print(io.recvline())

io.interactive()
