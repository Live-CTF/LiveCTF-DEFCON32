#!/usr/bin/env python3

from pwn import *
from hashlib import sha256
import json

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
#HOST, PORT = "localhost", "3000"


io = remote(HOST, int(PORT))

io.sendline(b'5')
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
data = json.loads(io.recvline())
print(data)
n = data["n"]

msg1=b'ls'
msg2=b'./submitter'

new_power = int.from_bytes(msg2, 'big') * pow(int.from_bytes(msg1, 'big'), -1, n) % n
hashed = int(sha256(msg2).hexdigest(),16)

ctxt1 = pow(data["ctxt"], new_power, data["n"]**2)

new_payload = {"hash": hashed, "ctxt": ctxt1, "n": n}
io.sendline(("4 " + json.dumps(new_payload)).encode())
print(io.recvall())
