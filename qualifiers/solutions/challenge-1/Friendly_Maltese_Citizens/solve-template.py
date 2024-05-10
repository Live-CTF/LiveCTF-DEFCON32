#!/usr/bin/env python3

from pwn import *
import hashlib
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#context.log_level = 'debug'
#log.info("output: %s\n%s\n%s\n%s\n", io.recvline(), io.recvline(), io.recvline(), io.recvline())
#io.interactive()
io.sendline("5")
io.recvuntil(b"{")
handout = json.loads((b"{" + io.recvline()).strip().decode())
n = handout["n"]
ct = handout["ctxt"]

s1 = b"ls"
s2 = b"./submitter"
x1 = int.from_bytes(s1, 'big')
x2 = int.from_bytes(s2, 'big')
x3 = (x2*pow(x1, -1, n)) % n
assert (x1*x3) % n == x2
new_ct = pow(ct, x3, n**2)
#print(new_ct)
assert int(hashlib.sha256(s1).hexdigest(), 16) == int(handout["hash"])

jj = json.dumps({"hash": int(hashlib.sha256(s2).hexdigest(), 16), "ctxt": new_ct, "n": n})


io.sendlineafter(b"shell\n", "4 " + jj)
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

