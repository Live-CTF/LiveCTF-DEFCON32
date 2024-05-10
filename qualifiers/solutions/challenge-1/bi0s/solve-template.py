#!/usr/bin/env python3

from pwn import *
import json
from hashlib import sha256

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendlineafter(b'> ', b'5')
for i in range(6):
    print(io.recvline())
jsonout = io.recvline().decode()
msg = json.loads(jsonout)
mult = int.from_bytes(b'./submitter                      ', 'big') // 27763
command = bytes.fromhex(hex(mult * 27763)[2:])
payload = pow(msg['ctxt'], mult, msg['n']**2)
io.sendlineafter(b'> ', b'4'+json.dumps({'hash': int(sha256(command).hexdigest(), 16),
                                    'ctxt': payload,
                                    'n': msg['n']}).encode())
for i in range(20):
    print(io.recvline())