#!/usr/bin/env python3

from pwn import *
import json
import hashlib

context.log_level = 'DEBUG'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendlineafter(b"> ", b"5")
io.recvuntil(b"{")
msg = json.loads(b"{" + io.recvline())

n = msg["n"]
ctxt = msg["ctxt"]

ls = int(b'ls'.hex(), 16)
submitter = b'./submitter'
target = int(submitter.hex(), 16)
div = target * pow(ls, -1, n) % n

ans = {}
ans["hash"] = int(hashlib.sha256(submitter).hexdigest(), 16)
ans["ctxt"] = pow(ctxt, div, n**2)
print(ans)


payload = json.dumps(ans).encode()
io.sendlineafter(b"> ", b"4 "+payload)

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)