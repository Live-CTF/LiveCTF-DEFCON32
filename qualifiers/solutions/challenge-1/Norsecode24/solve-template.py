#!/usr/bin/env python3

from pwn import *
import json
import os

import hashlib

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#io = process("./challenge")
io.recvuntil(b"> ")

io.sendline(b"5")
io.recvuntil(b'{')
data = b'{' + io.recvline()

msg = json.loads(data)
ctxt = msg['ctxt']
n = msg['n']

ptxt = b'ls'
ptxt_num = int.from_bytes(ptxt, 'big')

new_ptxt = b'./submitter'
new_ptxt_num = int.from_bytes(new_ptxt, 'big')
mul_factor = (pow(ptxt_num, -1, n) * new_ptxt_num) % n

new_ctxt = pow(ctxt, mul_factor, n**2)
new_hash = int(hashlib.sha256(new_ptxt).hexdigest(), 16)

val = {'hash': new_hash, 'ctxt': new_ctxt}
io.sendline("4 " + json.dumps(val))

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
print(f'Flag: {flag}')
