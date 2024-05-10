#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import json
import hashlib

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
io.recvuntil(b'> ')
io.sendline(b'5')
io.recvuntil(b'{')
ls_data = json.loads(b'{' + io.recvline())

ct = ls_data["ctxt"]

cmd = "./submitter"

ls_int = int.from_bytes(b"ls", 'big')
want = int.from_bytes(cmd.encode() + b" " + b"\x00"*2, "big")

left = ls_int - (want % ls_int)
left_bytes = long_to_bytes(left)
plb = cmd.encode() + b" " + (2-len(left_bytes))*b"\x00" + left_bytes
want2 = bytes_to_long(plb)
hash_int = int(hashlib.sha256(plb).hexdigest(), 16)

assert want2 % ls_int == 0
quot = want2 // ls_int

data = pow(ct, quot, ls_data["n"]**2)

payload = {
    "ctxt": data,
    "hash": hash_int
}

io.recvuntil(b"> ")
io.sendline(b"4" + json.dumps(payload).encode())

print(io.recvall(timeout=2))
