#!/usr/bin/env python3

import json
import hashlib
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

# io.recvline()
# io.recvuntil(b"Leave\n> ")
# io.recvline()
io.sendline(b'5')

io.recvuntil(b"{")

message = "{" + io.recvline().decode()
print("diff" * 20)
print(message)
print("diff" * 20)

message = json.loads(message)

n = message['n']
ctxt = message['ctxt']

n2 = n**2
ls_int = int.from_bytes(b'ls', 'big')

def encrypt_command(cmd):
    cmd_int = int.from_bytes(cmd, 'big')
    scalar = cmd_int * pow(ls_int, -1, n) % n
    return {
    'hash': int(hashlib.sha256(cmd).hexdigest(), 16),
    'ctxt': pow(ctxt, scalar, n2),
    }

payload = '4' + json.dumps(encrypt_command(b'./submitter'))

io.sendlineafter(b"> ", payload.encode())

# res = io.recvuntil(b"}").decode()

res = io.recvuntil(b"}").decode()

l = len(res.split("Live")[0])
flag = res[l:]

log.info(f"Flag: {flag}")

# log.info(res)
# io.interactive()