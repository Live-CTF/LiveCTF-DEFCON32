#!/usr/bin/env python3

from pwn import *
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.sendline(b"5")

output = io.recvuntil(b'}\n').decode().strip()
print(output)

data = json.loads(output.splitlines()[-1])
hash = data["hash"]
m1 = int.from_bytes(b"ls", "big")
c1 = data["ctxt"]
n = data["n"]


cmd = b"./submitter"
m_win = int.from_bytes(cmd, "big")
k = m_win * pow(m1, -1, n) % n

#print(io.recvall(timeout=2))
io.close()

io = remote(HOST, int(PORT))
payload = json.dumps({
    "hash": int(hashlib.sha256(cmd).hexdigest(), 16),
    "ctxt": pow(c1, k, n*n),
    "n": n,
}).encode()
io.sendline(b"4" + payload)

print(io.recvall(timeout=3).decode())
io.close()