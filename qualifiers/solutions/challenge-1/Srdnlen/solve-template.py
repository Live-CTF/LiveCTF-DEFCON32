#!/usr/bin/env python3

from pwn import remote, process, context
import hashlib, json, os, re

context.log_level = 'info'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

b2i = lambda b: int.from_bytes(b, 'big')
i2b = lambda i: i.to_bytes((i.bit_length() + 7) // 8, 'big')

io = remote(HOST, int(PORT))
# io = process("./challenge")

io.sendlineafter(b"> ", b"5")
io.recvuntil(b"{")
data = json.loads("{" + io.recvuntil(b"}\n").decode().strip())

n = data["n"]
n_sq = n**2
pt = b"ls"
ct = data["ctxt"]
h = data["hash"]

ls_out = io.recvline(keepends=False)

cmd = b"python3 -c __import__('os').system('./submitter');#dioporco"
h_ = int(hashlib.sha256(i2b(b2i(cmd) // b2i(pt) * b2i(pt))).hexdigest(), 16)
ct_ = pow(ct, b2i(cmd) // b2i(pt), n_sq)
data = json.dumps({'hash': h_, 'ctxt': ct_})
io.sendlineafter(b"> ", b"4" + data.encode())

data = io.recvrepeat(0.5)
flags = re.findall(r"\w+\{.*\}".encode(), data)

for flag in flags:
    print(flag)