#!/usr/bin/env python3

from pwn import *
import hashlib
import random
from math import gcd, lcm
import json
import os

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

io.sendlineafter(b'> ', b'5')
for _ in range(6):
    io.recvline().strip().decode()
data = io.recvline().strip().decode()
log.info(data)
data = json.loads(data)
hash = int(data['hash'])
ctxt = int(data['ctxt'])
n = int(data['n'])


ptxt = b'./submitter BHd'
h = int(hashlib.sha256(ptxt).hexdigest(), 16)



ctxt_sub = pow(ctxt, 8637685996160371807332146626828, n**2)
msg = {'hash': h, 'ctxt': ctxt_sub, 'n': n}
io.sendlineafter(b'> ', b'4 '+json.dumps(msg).encode())
flag = io.recvline_contains(b'Flag')
log.info(flag)



io.interactive()
