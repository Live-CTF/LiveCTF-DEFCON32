#!/usr/bin/env python3
import json

from pwn import *

context.log_level = 'DEBUG'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

io.sendlineafter(b"> ", b"5")
h = io.recvline_contains(b"hash").strip().decode()
print(h)
msg = json.loads(h)

io.close()

io = remote(HOST, int(PORT))

ct = msg["ctxt"]
n = msg["n"]
L = lambda x: (x-1)//n

ct_ = pow(ct,37098578866625978483691982771356672820766, n**2)
ptxt = b'./submitter     \x1f\xe7z'

solution = {
    "hash": int(hashlib.sha256(ptxt).hexdigest(), 16),
    "ctxt": ct_
}

io.sendlineafter(b"> ", b"4"+json.dumps(solution).encode())
print(io.recvall())

