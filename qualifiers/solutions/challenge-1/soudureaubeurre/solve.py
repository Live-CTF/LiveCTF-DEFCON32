#!/usr/bin/env python3
import json, hashlib
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

cmd1 = int.from_bytes(b"ls", 'big')
cmd2 = int.from_bytes(b"./submitter", 'big')

io = remote(HOST, int(PORT))
#io.interactive()
print(io.recvuntil(b">"))
io.send(b"5\n")
rsp = io.recvuntil(b">")
values = rsp.split(b"\n")[6]
#print(rsp)
values = json.loads(values)
n = values["n"]
c = values["ctxt"]

# New ciphertext
n_2 = n*n
m2 = (pow(cmd1, -1, n) * cmd2) % n
c = pow(c,m2,n_2)
hash_int = int(hashlib.sha256(b"./submitter").hexdigest(), 16)

values["ctxt"] = c
values["hash"] = hash_int
msg = json.dumps(values)
io.send(f"4 {msg}\n".encode())
rsp = io.recvline()
print(rsp)
