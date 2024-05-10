#!/usr/bin/env python3
import json
from pwn import *
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendline("5")
io.recvuntil(b"{")
recv = json.loads((b"{" + io.recvline()).strip().decode())
n = int(recv["n"])
ctxt = int(recv["ctxt"])

s1 = b"ls"
s2 = b"./submitter"
m1 = int.from_bytes(s1, 'big')
m2 = int.from_bytes(s2, 'big')

m3 = (m2 * pow(m1, -1, n)) % n

new_ctxt = pow(ctxt, m3, n**2)

pload = json.dumps({"hash": int(hashlib.sha256(s2).hexdigest(), 16), "ctxt": new_ctxt, "n": n})

io.sendlineafter("shell\n", "4 " + pload)
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)