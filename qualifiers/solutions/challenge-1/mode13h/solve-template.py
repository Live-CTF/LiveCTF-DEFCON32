#!/usr/bin/env python3

from pwn import *
#context.log_level = "debug"
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

io.sendlineafter(b"> ", b"5")

io.recvuntil(b"{")
resp = "{" + io.recvline().decode().strip()
resp = json.loads(resp)
n = int(resp["n"])
ct = int(resp["ctxt"])

pt = b'./submitter =3'
h = int(hashlib.sha256(pt).hexdigest(), 16)

new_pt = 33740960922501452372391197761
new_ct = pow(ct, new_pt, n**2)

io.sendlineafter(b"> ", b"4"+json.dumps({"hash":h, "ctxt":new_ct}).encode())

flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

io.interactive()
