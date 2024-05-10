#!/usr/bin/env python3

from pwn import *
import json
import hashlib

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT), level='error')
io.sendline(b"5")
line = b""
while b"{" not in line:
    line = io.recvline()

line = line.decode()
dat = json.loads(line)
io.close()

hsh = dat["hash"]
ctxt = dat["ctxt"]
n = dat["n"]

print("GOT DATA")
print(str(hsh)[:32])
print(str(ctxt)[:32])
print(str(n)[:32])

nsq = n**2

exp = int(b"./submitter abcdef".hex(), 16) // int(b"ls".hex(), 16)

ptxt_int = int(b"ls".hex(), 16) * exp
ptxt_hex = format(ptxt_int, 'x')
if len(ptxt_hex) % 2:
    ptxt_hex = '0' + ptxt_hex
ptxt = bytes.fromhex(ptxt_hex)
hash_int_new = int(hashlib.sha256(ptxt).hexdigest(), 16)

new_ctxt = pow(ctxt, exp, nsq)

print("got new ct")

new_data = {"n": n, "hash": hash_int_new, "ctxt": new_ctxt}

io = remote(HOST, int(PORT), level='error')
io.sendline(("4"+json.dumps(new_data)).encode())


flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)