#!/usr/bin/env python3

from pwn import *
import json


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

io.sendline(b"5")
context.log_level = "INFO"
io.recvuntil(b"submitter\n")
i=io.recvline()
j = json.loads(i)

S = b"./submitter # 6114"
X = 27763
Y = int.from_bytes(S, 'big') // X
c = pow(j["ctxt"],Y,j["n"]**2)
h = int(hashlib.sha256(S).hexdigest(), 16)
J = {"hash":h,"ctxt":c}

io.sendline(b"4 " + json.dumps(J).encode())

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
