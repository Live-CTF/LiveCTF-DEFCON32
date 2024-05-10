#!/usr/bin/env python3

from pwn import *
import json


HOST = os.environ.get("HOST", "localhost")
PORT = 31337

io = remote(HOST, int(PORT))
io.recvuntil(b"> ")
io.send(b"5\n")
io.recvuntil(b"{")
js = json.loads((b"{" + io.recvline().strip()).decode())
n = js["n"]
ctxt = js["ctxt"]
print(js)

def bytes_to_long(x):
    return int.from_bytes(x, "big")


i = 637
msg = b"sh -c ./submitter " + str(i).encode()
h = int(hashlib.sha256(msg).hexdigest(), 16)
assert bytes_to_long(msg) % 27763 == 0
magic = bytes_to_long(msg) // 27763
ctx = pow(ctxt, magic, n**2)

js = json.dumps(
    {
        "hash": h,
        "ctxt": ctx,
    }
)
print(js)

io.sendline(("4" + js).encode())
print(io.recvall())
